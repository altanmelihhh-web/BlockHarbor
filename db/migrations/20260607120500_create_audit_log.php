<?php declare(strict_types=1);

use Phinx\Migration\AbstractMigration;

final class CreateAuditLog extends AbstractMigration
{
    public function change(): void
    {
        $this->execute(<<<'SQL'
            CREATE TABLE audit_log (
                id              bigserial PRIMARY KEY,
                ts              timestamptz NOT NULL DEFAULT now(),
                actor_username  varchar(64),
                actor_role      varchar(16),
                ip_address      inet,
                action          varchar(64) NOT NULL,
                details         jsonb NOT NULL DEFAULT '{}'::jsonb,
                prev_hash       bytea,
                entry_hash      bytea NOT NULL
            );

            CREATE INDEX audit_log_ts_brin     ON audit_log USING brin (ts);
            CREATE INDEX audit_log_actor_time  ON audit_log (actor_username, ts DESC);
            CREATE INDEX audit_log_action_time ON audit_log (action,         ts DESC);

            -- Hash chain trigger: every INSERT computes
            --   prev_hash  = previous row's entry_hash (or \x00 for the first)
            --   entry_hash = sha256(prev_hash || canonical_json_of_this_row)
            CREATE OR REPLACE FUNCTION audit_chain_trigger() RETURNS trigger AS $$
            DECLARE
                last_hash bytea;
                canonical text;
            BEGIN
                SELECT entry_hash INTO last_hash
                FROM audit_log
                ORDER BY id DESC
                LIMIT 1;

                NEW.prev_hash := COALESCE(last_hash, '\x00'::bytea);

                canonical := jsonb_build_object(
                    'ts',      NEW.ts,
                    'actor',   NEW.actor_username,
                    'action',  NEW.action,
                    'details', NEW.details
                )::text;

                NEW.entry_hash := digest(NEW.prev_hash || convert_to(canonical, 'UTF8'), 'sha256');
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;

            CREATE TRIGGER audit_chain
                BEFORE INSERT ON audit_log
                FOR EACH ROW EXECUTE FUNCTION audit_chain_trigger();
        SQL);
    }
}
