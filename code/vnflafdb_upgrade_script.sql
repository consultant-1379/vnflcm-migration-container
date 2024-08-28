--*******************************************************************************
--* COPYRIGHT Ericsson 2022
--*
--* The copyright to the computer program(s) herein is the property of
--* Ericsson Inc. The programs may be used and/or copied only with written
--* permission from Ericsson Inc. or in accordance with the terms and
--* conditions stipulated in the agreement/contract under which the
--* program(s) have been supplied.
--*******************************************************************************
-- This sql script is common script and whenever there is new addition in schema append the content in this script.

-- Update this SQL file whenever their is change in vnflafdb schema as after db restore,
-- the vnflcm db schema will override the vmvnfm db schema

-- SM-11590 VM VNFM 22.12 for ETSI Error State Handling.
ALTER TABLE vnflifecycleoperation ADD COLUMN correlationid character varying(64),ADD COLUMN lastuseraction character varying(16);

-- SM-135409 Store allowed recovery action for a lcm operation at given failure stage.
ALTER TABLE vnflifecycleoperation ADD COLUMN allowedrecoveryactions character varying(255);

-- SM-147378 Migration script change for SOL v331 DB changes
CREATE OR REPLACE FUNCTION update_databaseschema_vnfsAndInstantiatedVnf() RETURNS void AS $$
BEGIN
ALTER TABLE vnfs ADD COLUMN IF NOT EXISTS extensions text;
-- To check if extensions column exists in instaantiatedvnf table, then only copy
DECLARE
  colname character varying(255);
BEGIN
  SELECT column_name into colname FROM information_schema.columns WHERE table_name='instantiatedvnf' and column_name='extensions';
IF coalesce(colname, '') != '' THEN
    UPDATE vnfs vnfinfo set extensions = (SELECT extensions FROM instantiatedvnf insinfo where insinfo.vnfid=vnfinfo.vnfid);
END IF;
END;
ALTER TABLE instantiatedvnf DROP COLUMN IF EXISTS extensions;
END
$$language plpgsql;
select update_databaseschema_vnfsAndInstantiatedVnf();

-- SM-155296 Migration script changes for pagination support
ALTER TABLE vnfs ADD COLUMN IF NOT EXISTS creationtime timestamp without time zone;

CREATE OR REPLACE FUNCTION update_Vnfs_CreationTime() RETURNS void AS $$
DECLARE
   vnfids text[] = array(select vnfid from vnfs);
   currTime timestamp = current_timestamp;
BEGIN
IF array_length(vnfids, 1) > 0
THEN
FOR i IN array_lower(vnfids, 1) .. array_upper(vnfids, 1) LOOP
  DECLARE
   vnf_id text;
  BEGIN
   vnf_id := vnfids[i];
   currTime := currTime + '2 seconds';
   currTime := TO_CHAR(currTime,'YYYY-MM-DD HH:MI:SS.MS');
   UPDATE vnfs set creationtime = currTime where vnfid = vnf_id;
  END;
END LOOP;
END IF;
END;
$$ language 'plpgsql';
select update_Vnfs_CreationTime();

-- SM-163393 Migration script changes to add new column for subscription API
ALTER TABLE nfvo ADD COLUMN IF NOT EXISTS tokenEndpoint character varying(512);
ALTER TABLE nfvo ADD COLUMN IF NOT EXISTS notificationTypes text;
ALTER TABLE nfvo ADD COLUMN IF NOT EXISTS operationTypes text;
ALTER TABLE nfvo ADD COLUMN IF NOT EXISTS operationStates text;

ALTER TABLE nfvo ADD CONSTRAINT subscriptionid_unique UNIQUE (subscriptionid);

-- [Eo-173140]: If VNFD does not have scaling_by_more_than_one_step_supported attribute, use default false

alter table vnfdescriptors alter column scalingbymorethanonestepsupported set default false;

CREATE TABLE requestprocessingdetails (
  request_id VARCHAR UNIQUE,
  request_hash VARCHAR NOT NULL,
  response_code INTEGER,
  response_headers VARCHAR,
  response_body VARCHAR,
  vnfLifeCycleOperationId VARCHAR,
  processing_state VARCHAR NOT NULL,
  retry_after INTEGER NOT NULL,
  creation_time TIMESTAMP NOT NULL,

  PRIMARY KEY (request_id)
);

ALTER TABLE nfvo ADD COLUMN IF NOT EXISTS idempotencyHeaderName character varying(512);

ALTER TABLE vims ADD COLUMN IF NOT EXISTS idempotencyHeaderName character varying(512);

ALTER TABLE vnflifecycleoperation ADD COLUMN IF NOT EXISTS notificationstatus smallint DEFAULT 0;