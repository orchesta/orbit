ALTER TABLE repositories DROP COLUMN git_host_id;
ALTER TABLE access_tokens DROP COLUMN git_host_id;
ALTER TABLE access_tokens ALTER COLUMN provider TYPE VARCHAR(20);
DROP TABLE git_hosts;
