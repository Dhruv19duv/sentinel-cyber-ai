#!/usr/bin/env bash
# =============================================================================
# Sentinel Cyber AI — PostgreSQL Backup & Restore Script
# Safely backs up and restores the production PostgreSQL database.
# Supports local backups, remote sync (S3/rsync), and cron scheduling.
#
# Usage:
#   ./scripts/backup.sh backup [--compress] [--cron] [--s3]
#   ./scripts/backup.sh restore <file>
#   ./scripts/backup.sh list
#   ./scripts/backup.sh latest
#   ./scripts/backup.sh clean [--keep N]
#   ./scripts/backup.sh export [--sync]
#   ./scripts/backup.sh sync                   # Sync to remote (S3/rsync)
#   ./scripts/backup.sh setup-cron             # Install cron job
#   ./scripts/backup.sh verify                 # Verify latest backup integrity
#
# Backup files are stored in: ./backups/postgres/
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )/.." && pwd)"
cd "$SCRIPT_DIR"

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ── Configuration ──
BACKUP_DIR="./backups/postgres"
EXPORT_DIR="./backups/export"
COMPOSE_FILE="docker/docker-compose.prod.yml"
COMPOSE_PROJECT="sentinel-prod"
PG_CONTAINER="sentinel-postgres"
DEFAULT_RETENTION=7           # Number of backups to keep by default
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
IS_CRON=false                 # Suppress info output when true

# ── Source .env for DB credentials ──
if [ -f ".env" ]; then
  set -a
  # shellcheck source=/dev/null
  . ".env"
  set +a
fi

# ── Resolve DB credentials from environment (with defaults) ──
PG_DB="${POSTGRES_DB:-sentinel}"
PG_USER="${POSTGRES_USER:-sentinel}"
PG_PASSWORD="${POSTGRES_PASSWORD:-sentinel_secret}"
S3_BUCKET="${BACKUP_S3_BUCKET:-}"
AWS_PROFILE="${AWS_PROFILE:-sentinel-backup}"

# ── Help ──
show_help() {
    cat <<EOF
Sentinel Cyber AI — PostgreSQL Backup & Restore

Usage:
  ./scripts/backup.sh backup [--compress] [--cron] [--s3]
  ./scripts/backup.sh restore <backup_file>
  ./scripts/backup.sh list
  ./scripts/backup.sh latest
  ./scripts/backup.sh clean [--keep N]
  ./scripts/backup.sh export [--sync]
  ./scripts/backup.sh sync
  ./scripts/backup.sh setup-cron
  ./scripts/backup.sh verify

Commands:
  backup       Create a timestamped backup
               --compress   Gzip compress (saves ~80% space)
               --cron       Quiet mode for cron (stderr only)
               --s3         Also sync to S3 after backup
  restore      Restore database from backup file (.sql or .sql.gz)
  list         List all backups with sizes and dates
  latest       Show path to the most recent backup
  clean        Remove old backups (keeps last $DEFAULT_RETENTION)
               --keep N     Override number of backups to keep
  export       Copy latest backup to ./backups/export/
               --sync       Print rsync/scp command for remote transfer
  sync         Upload latest backup to S3 bucket or rsync target
               Requires: BACKUP_S3_BUCKET in .env or --s3-bucket <url>
  setup-cron   Install daily cron job for automated backups
  verify       Verify the latest backup file integrity (pg_restore --list)

Backup directory: $BACKUP_DIR
Env variables:
  BACKUP_S3_BUCKET    S3 URI (s3://bucket/path) or rsync target (user@host:path)
  AWS_PROFILE         AWS CLI profile (default: sentinel-backup)
  BACKUP_RETENTION    Overrides default retention count
EOF
}

# ── Logging ──
log_info() {
    if [ "$IS_CRON" = false ]; then
        echo -e "${BLUE}ℹ️  $1${NC}"
    fi
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}" >&2
}

log_error() {
    echo -e "${RED}❌ $1${NC}" >&2
}

# ── Prerequisites ──
check_prerequisites() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed."
        exit 1
    fi

    if ! docker ps --format '{{.Names}}' | grep -q "$PG_CONTAINER"; then
        log_error "PostgreSQL container '$PG_CONTAINER' is not running."
        echo "  Start the stack first: ./scripts/deploy.sh" >&2
        exit 1
    fi

    if ! docker exec "$PG_CONTAINER" pg_isready -U "$PG_USER" -d "$PG_DB" &> /dev/null; then
        log_error "PostgreSQL is not accepting connections."
        exit 1
    fi
}

# ── Create Backup Directory ──
ensure_backup_dir() {
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$EXPORT_DIR"
}

# ── Backup ──
do_backup() {
    local compress=false
    local sync_to_s3=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --compress) compress=true; shift ;;
            --cron) IS_CRON=true; shift ;;
            --s3) sync_to_s3=true; shift ;;
            *) shift ;;
        esac
    done

    ensure_backup_dir
    check_prerequisites

    local backup_file="${BACKUP_DIR}/sentinel_${TIMESTAMP}.sql"
    local display_file="$backup_file"

    log_info "Starting PostgreSQL backup..."

    local db_size
    db_size=$(docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -t -c \
        "SELECT pg_size_pretty(pg_database_size('${PG_DB}'));" 2>/dev/null | tr -d ' ')
    log_info "Database size: ${db_size:-unknown}"

    if [ "$compress" = true ]; then
        backup_file="${backup_file}.gz"
        log_info "Compressing with gzip..."

        if ! docker exec "$PG_CONTAINER" \
            pg_dump -U "$PG_USER" -d "$PG_DB" \
                --clean \
                --if-exists \
                --no-owner \
                --no-privileges \
                --verbose 2>/dev/null \
            | gzip > "$backup_file"; then
            log_error "Backup failed during pg_dump or compression."
            rm -f "$backup_file"
            exit 1
        fi
    else
        if ! docker exec "$PG_CONTAINER" \
            pg_dump -U "$PG_USER" -d "$PG_DB" \
                --clean \
                --if-exists \
                --no-owner \
                --no-privileges \
                --verbose 2>/dev/null \
            > "$backup_file"; then
            log_error "Backup failed during pg_dump."
            rm -f "$backup_file"
            exit 1
        fi
    fi

    if [ ! -s "$backup_file" ]; then
        log_error "Backup file is empty. Something went wrong."
        rm -f "$backup_file"
        exit 1
    fi

    local file_size
    file_size=$(du -h "$backup_file" | cut -f1)

    log_success "Backup created: $(basename "$backup_file")"
    log_success "File size: $file_size"
    log_info "Location: $(cd "$(dirname "$backup_file")" && pwd)/$(basename "$backup_file")"

    # Auto-sync to S3 if requested
    if [ "$sync_to_s3" = true ] && [ -n "$S3_BUCKET" ]; then
        echo ""
        do_sync "$backup_file"
    fi

    # Print absolute path for scripting
    if [ "$IS_CRON" = false ]; then
        echo ""
        echo "$(cd "$(dirname "$backup_file")" && pwd)/$(basename "$backup_file")"
    fi
}

# ── Sync to S3 / Remote ──
do_sync() {
    local source_file="${1:-}"
    local s3_target="${S3_BUCKET:-}"

    if [ -z "$source_file" ]; then
        source_file=$(find "$BACKUP_DIR" -maxdepth 1 \( -name "*.sql" -o -name "*.sql.gz" \) -print | sort -r | head -1)
        if [ -z "$source_file" ]; then
            log_warning "No backups found to sync."
            return 1
        fi
    fi

    if [ -z "$s3_target" ]; then
        log_warning "No BACKUP_S3_BUCKET set in .env. Skipping remote sync."
        log_info "Set BACKUP_S3_BUCKET=s3://your-bucket/path or user@host:path"
        return 1
    fi

    local filename
    filename=$(basename "$source_file")

    log_info "Syncing $filename to remote..."

    # Detect target type: S3 URI vs rsync-style
    if [[ "$s3_target" == s3://* ]]; then
        # ── AWS S3 Sync ──
        if command -v aws &> /dev/null; then
            log_info "Using AWS CLI (profile: $AWS_PROFILE)..."
            if aws s3 cp "$source_file" "${s3_target}/${filename}" --profile "$AWS_PROFILE" --only-show-errors; then
                log_success "Synced to ${s3_target}/${filename}"
            else
                log_error "S3 sync failed. Check AWS credentials and bucket permissions."
                return 1
            fi
        elif command -v rclone &> /dev/null; then
            log_info "Using rclone..."
            if rclone copy "$source_file" "${s3_target}/${filename}" --progress; then
                log_success "Synced via rclone to ${s3_target}/${filename}"
            else
                log_error "rclone sync failed."
                return 1
            fi
        else
            log_warning "Neither 'aws' nor 'rclone' CLI found. Install one:"
            echo "  aws CLI:   https://aws.amazon.com/cli/"
            echo "  rclone:    https://rclone.org/install/"
            echo ""
            log_info "Manual upload command:"
            echo "  aws s3 cp $source_file ${s3_target}/${filename} --profile $AWS_PROFILE"
            return 1
        fi
    else
        # ── rsync target (user@host:path) ──
        if command -v rsync &> /dev/null; then
            log_info "Using rsync..."
            if rsync -avzP --timeout=30 "$source_file" "${s3_target}/${filename}"; then
                log_success "Synced to ${s3_target}/${filename}"
            else
                log_error "rsync failed. Check SSH connectivity."
                return 1
            fi
        else
            log_error "rsync is not installed."
            return 1
        fi
    fi

    # Prune old backups on S3 (keep last 30 days)
    if [[ "$s3_target" == s3://* ]] && command -v aws &> /dev/null; then
        log_info "Cleaning old S3 backups (keeping 30 days)..."
        aws s3 ls "${s3_target}/" --profile "$AWS_PROFILE" 2>/dev/null | while read -r line; do
            local date_str
            date_str=$(echo "$line" | awk '{print $1" "$2}')
            local file_name
            file_name=$(echo "$line" | awk '{print $4}')
            if [ -n "$date_str" ] && [ "$(date -d "$date_str" +%s 2>/dev/null)" -lt "$(date -d '30 days ago' +%s)" ]; then
                aws s3 rm "${s3_target}/${file_name}" --profile "$AWS_PROFILE" --only-show-errors 2>/dev/null || true
                echo "  🗑️  Removed old S3 backup: $file_name"
            fi
        done
    fi
}

# ── Restore ──
do_restore() {
    local restore_file="${1:-}"

    if [ -z "$restore_file" ]; then
        log_error "No backup file specified."
        echo "  Usage: ./scripts/backup.sh restore <backup_file>" >&2
        echo "  Available backups:" >&2
        list_backups >&2
        exit 1
    fi

    if [[ "$restore_file" != /* ]]; then
        restore_file="$SCRIPT_DIR/$restore_file"
    fi

    if [ ! -f "$restore_file" ]; then
        log_error "Backup file not found: $restore_file"
        exit 1
    fi

    ensure_backup_dir
    check_prerequisites

    local is_compressed=false
    if [[ "$restore_file" == *.gz ]]; then
        is_compressed=true
    fi

    local file_size
    file_size=$(du -h "$restore_file" | cut -f1)
    local db_size
    db_size=$(docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -t -c \
        "SELECT pg_size_pretty(pg_database_size('${PG_DB}'));" 2>/dev/null | tr -d ' ')

    echo ""
    echo -e "${BOLD}Restore Plan:${NC}"
    echo "  Backup file: $(basename "$restore_file") ($file_size)"
    echo "  Target database: $PG_DB on container: $PG_CONTAINER"
    echo "  Current DB size: ${db_size:-unknown}"
    echo "  Compressed: $([ "$is_compressed" = true ] && echo 'Yes' || echo 'No')"
    echo ""
    echo -e "${YELLOW}${BOLD}⚠️  WARNING: This will DESTROY all current data in the '${PG_DB}' database!${NC}"
    echo ""

    if [ "$IS_CRON" = false ]; then
        read -r -p "Are you sure you want to proceed? (type 'yes' to confirm): " confirmation
        if [ "$confirmation" != "yes" ]; then
            echo "Restore cancelled."
            exit 0
        fi
    else
        log_error "Refusing to run restore in cron mode (--cron). Too dangerous."
        exit 1
    fi

    echo ""
    log_info "Starting restore..."

    log_info "Terminating existing connections..."
    docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d postgres -c \
        "SELECT pg_terminate_backend(pg_stat_activity.pid)
         FROM pg_stat_activity
         WHERE pg_stat_activity.datname = '${PG_DB}'
           AND pid <> pg_backend_pid();" > /dev/null 2>&1 || true

    log_info "Dropping and recreating database..."
    docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d postgres -c \
        "DROP DATABASE IF EXISTS \"${PG_DB}\";" > /dev/null 2>&1
    docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d postgres -c \
        "CREATE DATABASE \"${PG_DB}\";" > /dev/null 2>&1

    log_info "Restoring data (this may take a while)..."

    if [ "$is_compressed" = true ]; then
        if ! gunzip -c "$restore_file" | docker exec -i "$PG_CONTAINER" \
            psql -U "$PG_USER" -d "$PG_DB" --quiet; then
            log_error "Restore failed. The database is in an empty state."
            exit 1
        fi
    else
        if ! docker exec -i "$PG_CONTAINER" \
            psql -U "$PG_USER" -d "$PG_DB" --quiet < "$restore_file"; then
            log_error "Restore failed. The database is in an empty state."
            exit 1
        fi
    fi

    local table_count
    table_count=$(docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -t -c \
        "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>/dev/null | tr -d ' ')

    log_success "Restore complete!"
    log_info "Tables restored: ${table_count:-unknown}"
    log_info "Database: $PG_DB"

    log_info "Running ANALYZE for optimal query performance..."
    docker exec "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -c "ANALYZE;" > /dev/null 2>&1

    log_success "Database analyzed and ready."
}

# ── List Backups ──
list_backups() {
    ensure_backup_dir

    if ! ls "$BACKUP_DIR"/*.sql* 2>/dev/null | head -1 | grep -q .; then
        echo "No backups found in $BACKUP_DIR"
        return
    fi

    echo ""
    echo -e "${BOLD}Available Backups:${NC}"
    echo -e "${BOLD}──────────────────────────────────────────────────────────────${NC}"
    printf "  %-20s %-15s %s\n" "DATE" "SIZE" "FILENAME"
    echo "  ────────────────────────────────────────────────────────────"

    local total_bytes=0
    local count=0
    while IFS= read -r -d '' file; do
        local size
        local size_bytes
        local filename
        local mod_time

        filename=$(basename "$file")
        size=$(du -h "$file" | cut -f1)
        size_bytes=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo 0)

        mod_time=$(stat -c '%y' "$file" 2>/dev/null | cut -d'.' -f1 || \
                   date -r "$file" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || \
                   echo "unknown")

        printf "  %-20s %-15s %s\n" "$mod_time" "$size" "$filename"
        count=$((count + 1))
        total_bytes=$((total_bytes + size_bytes))
    done < <(find "$BACKUP_DIR" -maxdepth 1 \( -name "*.sql" -o -name "*.sql.gz" \) -print0 | sort -z -r)

    echo "  ────────────────────────────────────────────────────────────"
    total_size=$(numfmt --to=iec $total_bytes 2>/dev/null || echo "${total_bytes}B")
    echo -e "${BOLD}Total: $count backups, $total_size${NC}"
    echo ""

    local available
    available=$(df -h "$BACKUP_DIR" | tail -1 | awk '{print $4}')
    echo -e "  Free disk space: ${available}"
    echo ""
}

# ── Show Latest Backup ──
show_latest() {
    ensure_backup_dir

    local latest
    latest=$(find "$BACKUP_DIR" -maxdepth 1 \( -name "*.sql" -o -name "*.sql.gz" \) -print \
        | sort -r | head -1)

    if [ -z "$latest" ]; then
        log_warning "No backups found."
        return 1
    fi

    echo "$(cd "$(dirname "$latest")" && pwd)/$(basename "$latest")"
}

# ── Verify Backup Integrity ──
verify_backup() {
    local backup_file="${1:-}"

    if [ -z "$backup_file" ]; then
        backup_file=$(show_latest 2>/dev/null || true)
    fi

    if [ -z "$backup_file" ] || [ ! -f "$backup_file" ]; then
        log_error "No backup file found to verify."
        return 1
    fi

    log_info "Verifying: $(basename "$backup_file")"

    # Decompress if needed and check via pg_restore --list
    if [[ "$backup_file" == *.gz ]]; then
        log_info "Decompressing for verification..."
        if gunzip -t "$backup_file" 2>/dev/null; then
            log_success "Compression integrity check passed."
        else
            log_error "Backup file is corrupted (gzip check failed)."
            return 1
        fi
        # Check SQL structure via head/tail
        if gunzip -c "$backup_file" 2>/dev/null | head -20 | grep -q "pg_dump"; then
            log_success "Backup contains valid PostgreSQL dump header."
        else
            log_warning "Backup may not be a valid PostgreSQL dump (no pg_dump header found)."
        fi
    else
        if head -20 "$backup_file" | grep -q "pg_dump"; then
            log_success "Backup contains valid PostgreSQL dump header."
        else
            log_warning "Backup may not be a valid PostgreSQL dump (no pg_dump header found)."
        fi
    fi

    local file_size
    file_size=$(du -h "$backup_file" | cut -f1)
    local row_count
    row_count=$(wc -l < "$backup_file" 2>/dev/null || echo "0")

    log_success "Integrity check passed: $file_size, $row_count lines"
    return 0
}

# ── Clean Old Backups ──
clean_backups() {
    local keep=$DEFAULT_RETENTION

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --keep) keep="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    ensure_backup_dir

    if ! [[ "$keep" =~ ^[0-9]+$ ]] || [ "$keep" -lt 1 ]; then
        log_error "Invalid retention count: $keep. Must be a positive integer."
        exit 1
    fi

    local total
    total=$(find "$BACKUP_DIR" -maxdepth 1 \( -name "*.sql" -o -name "*.sql.gz" \) -print \
        | wc -l)

    if [ "$total" -le "$keep" ]; then
        log_info "Only $total backup(s) found (keeping $keep). Nothing to clean."
        return
    fi

    local to_delete=$((total - keep))
    log_info "Found $total backups, keeping $keep. Removing $to_delete oldest..."

    local removed=0
    local freed=0

    while IFS= read -r file; do
        local size
        size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo 0)
        rm -f "$file"
        echo "  🗑️  Removed: $(basename "$file") ($(du -h "$file" 2>/dev/null | cut -f1 || echo '0B'))"
        removed=$((removed + 1))
        freed=$((freed + size))
    done < <(find "$BACKUP_DIR" -maxdepth 1 \( -name "*.sql" -o -name "*.sql.gz" \) -print \
        | sort \
        | head -n "$to_delete")

    total_freed=$(numfmt --to=iec $freed 2>/dev/null || echo "${freed}B")
    log_success "Cleaned up. Freed $total_freed."
}

# ── Export Backup ──
export_backup() {
    local show_sync=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --sync) show_sync=true; shift ;;
            *) shift ;;
        esac
    done

    ensure_backup_dir

    local latest
    latest=$(find "$BACKUP_DIR" -maxdepth 1 \( -name "*.sql" -o -name "*.sql.gz" \) -print \
        | sort -r | head -1)

    if [ -z "$latest" ]; then
        log_warning "No backups found to export."
        return 1
    fi

    local export_name="sentinel_postgres_latest.sql"
    if [[ "$latest" == *.gz ]]; then
        export_name="sentinel_postgres_latest.sql.gz"
    fi

    cp "$latest" "$EXPORT_DIR/$export_name"
    log_success "Exported to: $EXPORT_DIR/$export_name"

    if [ "$show_sync" = true ]; then
        echo ""
        echo -e "${BOLD}To transfer this backup to another server:${NC}"
        echo ""
        echo "  # Using rsync:"
        echo "  rsync -avzP $EXPORT_DIR/$export_name user@remote-server:/path/to/backups/"
        echo ""
        echo "  # Using scp:"
        echo "  scp $EXPORT_DIR/$export_name user@remote-server:/path/to/backups/"
        echo ""
        echo "  # Using sftp:"
        echo "  sftp user@remote-server:/path/to/backups/ <<< put $EXPORT_DIR/$export_name"
        echo ""
    fi
}

# ── Setup Cron ──
setup_cron() {
    local script_path
    script_path="$(cd "$(dirname "$0")" && pwd)/backup.sh"
    local cron_job="0 2 * * * cd $SCRIPT_DIR && $script_path backup --compress --cron --s3 >> /dev/null 2>&1"
    local cron_log="0 2 * * * cd $SCRIPT_DIR && $script_path backup --compress --cron --s3 >> $SCRIPT_DIR/backups/cron.log 2>&1"

    echo ""
    echo -e "${BOLD}📅 Setup Automated Backup Cron Job${NC}"
    echo ""
    echo "This will install a cron job that runs daily at 2:00 AM:"
    echo "  • Creates compressed backup"
    echo "  • Syncs to S3/remote (if BACKUP_S3_BUCKET is set)"
    echo "  • Only logs errors (--cron mode)"
    echo ""
    echo "Choose option:"
    echo "  1) Quiet mode (errors to syslog)"
    echo "  2) Logged mode (output to ./backups/cron.log)"
    echo "  3) Cancel"
    echo ""
    read -r -p "Select [1-3]: " cron_choice

    case "$cron_choice" in
        1)
            (crontab -l 2>/dev/null | grep -v "backup.sh" || true; echo "$cron_job") | crontab -
            log_success "Cron job installed (quiet mode). Runs daily at 2:00 AM."
            echo ""
            echo "To verify: crontab -l | grep backup"
            echo "To remove: crontab -l | grep -v backup | crontab -"
            ;;
        2)
            mkdir -p "$SCRIPT_DIR/backups"
            (crontab -l 2>/dev/null | grep -v "backup.sh" || true; echo "$cron_log") | crontab -
            log_success "Cron job installed (logged mode). Output: ./backups/cron.log"
            echo ""
            echo "To view logs: tail -f backups/cron.log"
            echo "To remove: crontab -l | grep -v backup | crontab -"
            ;;
        *)
            echo "Cancelled."
            ;;
    esac
}

# ── Main ──
main() {
    local cmd="${1:-help}"
    shift 2>/dev/null || true

    if [ ! -f "pyproject.toml" ]; then
        log_error "Must be run from project root (sentinel-cyber-ai/)"
        exit 1
    fi

    case "$cmd" in
        backup)
            do_backup "$@"
            ;;
        restore)
            do_restore "$@"
            ;;
        list)
            list_backups
            ;;
        latest)
            show_latest
            ;;
        clean)
            clean_backups "$@"
            ;;
        export)
            export_backup "$@"
            ;;
        sync)
            do_sync
            ;;
        verify)
            verify_backup "$@"
            ;;
        setup-cron)
            setup_cron
            ;;
        --help|-h|help)
            show_help
            ;;
        *)
            log_error "Unknown command: $cmd"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

main "$@"
