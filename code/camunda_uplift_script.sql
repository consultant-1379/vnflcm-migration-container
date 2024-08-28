--*******************************************************************************
--* COPYRIGHT Ericsson 2020
--*
--* The copyright to the computer program(s) herein is the property of
--* Ericsson Inc. The programs may be used and/or copied only with written
--* permission from Ericsson Inc. or in accordance with the terms and
--* conditions stipulated in the agreement/contract under which the
--* program(s) have been supplied.
--*******************************************************************************
-- This sql script uplift camunda postgres schema from 7.9 to 7.11


-- https://app.camunda.com/jira/browse/CAM-9523
-- postgres_engine_7.9_patch_7.9.6_to_7.9.7_1.sql
create index ACT_IDX_HI_TASK_INST_START on ACT_HI_TASKINST(START_TIME_);
create index ACT_IDX_HI_TASK_INST_END on ACT_HI_TASKINST(END_TIME_);

-- https://app.camunda.com/jira/browse/CAM-9525
-- postgres_engine_7.9_patch_7.9.6_to_7.9.7_2.sql
create index ACT_IDX_HI_OP_LOG_TIMESTAMP on ACT_HI_OP_LOG(TIMESTAMP_);


--  postgres_engine_7.9_to_7.10.sql
-- https://app.camunda.com/jira/browse/CAM-9084
ALTER TABLE ACT_RE_PROCDEF
  ADD STARTABLE_ BOOLEAN NOT NULL DEFAULT TRUE;

-- https://app.camunda.com/jira/browse/CAM-9153
ALTER TABLE ACT_HI_VARINST
  ADD CREATE_TIME_ TIMESTAMP;

-- https://app.camunda.com/jira/browse/CAM-9215
ALTER TABLE ACT_HI_ATTACHMENT
  ADD CREATE_TIME_ TIMESTAMP;

-- https://app.camunda.com/jira/browse/CAM-9216
ALTER TABLE ACT_HI_DEC_IN
  ADD CREATE_TIME_ TIMESTAMP;

-- https://app.camunda.com/jira/browse/CAM-9217
ALTER TABLE ACT_HI_DEC_OUT
  ADD CREATE_TIME_ TIMESTAMP;

-- https://app.camunda.com/jira/browse/CAM-9199
ALTER TABLE ACT_HI_PROCINST
  ADD ROOT_PROC_INST_ID_ varchar(64);
create index ACT_IDX_HI_PRO_INST_ROOT_PI on ACT_HI_PROCINST(ROOT_PROC_INST_ID_);

-- https://app.camunda.com/jira/browse/CAM-9200
ALTER TABLE ACT_HI_PROCINST
  ADD REMOVAL_TIME_ timestamp;
create index ACT_IDX_HI_PRO_INST_RM_TIME on ACT_HI_PROCINST(REMOVAL_TIME_);

-- https://app.camunda.com/jira/browse/CAM-9230
ALTER TABLE ACT_HI_BATCH
  ADD CREATE_USER_ID_ varchar(255);
ALTER TABLE ACT_RU_BATCH
  ADD CREATE_USER_ID_ varchar(255);

-- https://app.camunda.com/jira/browse/CAM-9270
ALTER TABLE ACT_HI_DECINST
  ADD ROOT_PROC_INST_ID_ varchar(64);
create index ACT_IDX_HI_DEC_INST_ROOT_PI on ACT_HI_DECINST(ROOT_PROC_INST_ID_);

-- https://app.camunda.com/jira/browse/CAM-9270
ALTER TABLE ACT_HI_DECINST
  ADD REMOVAL_TIME_ timestamp;
create index ACT_IDX_HI_DEC_INST_RM_TIME on ACT_HI_DECINST(REMOVAL_TIME_);

-- https://app.camunda.com/jira/browse/CAM-9322
ALTER TABLE ACT_GE_BYTEARRAY
  ADD TYPE_ integer;

ALTER TABLE ACT_GE_BYTEARRAY
  ADD CREATE_TIME_ timestamp;

-- https://app.camunda.com/jira/browse/CAM-9370
ALTER TABLE ACT_RU_EXECUTION
  ADD ROOT_PROC_INST_ID_ varchar(64);

create index ACT_IDX_EXE_ROOT_PI on ACT_RU_EXECUTION(ROOT_PROC_INST_ID_);

-- https://app.camunda.com/jira/browse/CAM-9371
ALTER TABLE ACT_HI_ACTINST
  ADD ROOT_PROC_INST_ID_ varchar(64);

create index ACT_IDX_HI_ACTINST_ROOT_PI on ACT_HI_ACTINST(ROOT_PROC_INST_ID_);

-- https://app.camunda.com/jira/browse/CAM-9372
ALTER TABLE ACT_HI_TASKINST
  ADD ROOT_PROC_INST_ID_ varchar(64);

create index ACT_IDX_HI_TASKINST_ROOT_PI on ACT_HI_TASKINST(ROOT_PROC_INST_ID_);

-- https://app.camunda.com/jira/browse/CAM-9373
ALTER TABLE ACT_HI_VARINST
  ADD ROOT_PROC_INST_ID_ varchar(64);

create index ACT_IDX_HI_VARINST_ROOT_PI on ACT_HI_VARINST(ROOT_PROC_INST_ID_);

-- https://app.camunda.com/jira/browse/CAM-9374
ALTER TABLE ACT_HI_DETAIL
  ADD ROOT_PROC_INST_ID_ varchar(64);

create index ACT_IDX_HI_DETAIL_ROOT_PI on ACT_HI_DETAIL(ROOT_PROC_INST_ID_);

-- https://app.camunda.com/jira/browse/CAM-9375
ALTER TABLE ACT_HI_COMMENT
  ADD ROOT_PROC_INST_ID_ varchar(64);

create index ACT_IDX_HI_COMMENT_ROOT_PI on ACT_HI_COMMENT(ROOT_PROC_INST_ID_);

-- https://app.camunda.com/jira/browse/CAM-9376
ALTER TABLE ACT_HI_ATTACHMENT
  ADD ROOT_PROC_INST_ID_ varchar(64);

create index ACT_IDX_HI_ATTACHMENT_ROOT_PI on ACT_HI_ATTACHMENT(ROOT_PROC_INST_ID_);

-- https://app.camunda.com/jira/browse/CAM-9377
ALTER TABLE ACT_HI_INCIDENT
  ADD ROOT_PROC_INST_ID_ varchar(64);

create index ACT_IDX_HI_INCIDENT_ROOT_PI on ACT_HI_INCIDENT(ROOT_PROC_INST_ID_);

-- https://app.camunda.com/jira/browse/CAM-9390
ALTER TABLE ACT_HI_EXT_TASK_LOG
  ADD ROOT_PROC_INST_ID_ varchar(64);

create index ACT_HI_EXT_TASK_LOG_ROOT_PI on ACT_HI_EXT_TASK_LOG(ROOT_PROC_INST_ID_);

-- https://app.camunda.com/jira/browse/CAM-9391
ALTER TABLE ACT_HI_IDENTITYLINK
  ADD ROOT_PROC_INST_ID_ varchar(64);

create index ACT_IDX_HI_IDENT_LNK_ROOT_PI on ACT_HI_IDENTITYLINK(ROOT_PROC_INST_ID_);

-- https://app.camunda.com/jira/browse/CAM-9392
ALTER TABLE ACT_HI_JOB_LOG
  ADD ROOT_PROC_INST_ID_ varchar(64);

create index ACT_IDX_HI_JOB_LOG_ROOT_PI on ACT_HI_JOB_LOG(ROOT_PROC_INST_ID_);

-- https://app.camunda.com/jira/browse/CAM-9393
ALTER TABLE ACT_HI_OP_LOG
  ADD ROOT_PROC_INST_ID_ varchar(64);

create index ACT_IDX_HI_OP_LOG_ROOT_PI on ACT_HI_OP_LOG(ROOT_PROC_INST_ID_);

-- https://app.camunda.com/jira/browse/CAM-9407
ALTER TABLE ACT_HI_DEC_IN
  ADD ROOT_PROC_INST_ID_ varchar(64);

create index ACT_IDX_HI_DEC_IN_ROOT_PI on ACT_HI_DEC_IN(ROOT_PROC_INST_ID_);

ALTER TABLE ACT_HI_DEC_OUT
  ADD ROOT_PROC_INST_ID_ varchar(64);

create index ACT_IDX_HI_DEC_OUT_ROOT_PI on ACT_HI_DEC_OUT(ROOT_PROC_INST_ID_);

-- https://app.camunda.com/jira/browse/CAM-9388
ALTER TABLE ACT_GE_BYTEARRAY
  ADD ROOT_PROC_INST_ID_ varchar(64);

create index ACT_IDX_BYTEARRAY_ROOT_PI on ACT_GE_BYTEARRAY(ROOT_PROC_INST_ID_);

-- https://app.camunda.com/jira/browse/CAM-9416
ALTER TABLE ACT_HI_ACTINST
  ADD REMOVAL_TIME_ timestamp;

create index ACT_IDX_HI_ACT_INST_RM_TIME on ACT_HI_ACTINST(REMOVAL_TIME_);

ALTER TABLE ACT_HI_TASKINST
  ADD REMOVAL_TIME_ timestamp;

create index ACT_IDX_HI_TASK_INST_RM_TIME on ACT_HI_TASKINST(REMOVAL_TIME_);

ALTER TABLE ACT_HI_VARINST
  ADD REMOVAL_TIME_ timestamp;

create index ACT_IDX_HI_VARINST_RM_TIME on ACT_HI_VARINST(REMOVAL_TIME_);

ALTER TABLE ACT_HI_DETAIL
  ADD REMOVAL_TIME_ timestamp;

create index ACT_IDX_HI_DETAIL_RM_TIME on ACT_HI_DETAIL(REMOVAL_TIME_);

ALTER TABLE ACT_HI_COMMENT
  ADD REMOVAL_TIME_ timestamp;

create index ACT_IDX_HI_COMMENT_RM_TIME on ACT_HI_COMMENT(REMOVAL_TIME_);

ALTER TABLE ACT_HI_ATTACHMENT
  ADD REMOVAL_TIME_ timestamp;

create index ACT_IDX_HI_ATTACHMENT_RM_TIME on ACT_HI_ATTACHMENT(REMOVAL_TIME_);

ALTER TABLE ACT_HI_INCIDENT
  ADD REMOVAL_TIME_ timestamp;

create index ACT_IDX_HI_INCIDENT_RM_TIME on ACT_HI_INCIDENT(REMOVAL_TIME_);

ALTER TABLE ACT_HI_EXT_TASK_LOG
  ADD REMOVAL_TIME_ timestamp;

create index ACT_HI_EXT_TASK_LOG_RM_TIME on ACT_HI_EXT_TASK_LOG(REMOVAL_TIME_);

ALTER TABLE ACT_HI_IDENTITYLINK
  ADD REMOVAL_TIME_ timestamp;

create index ACT_IDX_HI_IDENT_LINK_RM_TIME on ACT_HI_IDENTITYLINK(REMOVAL_TIME_);

ALTER TABLE ACT_HI_JOB_LOG
  ADD REMOVAL_TIME_ timestamp;

create index ACT_IDX_HI_JOB_LOG_RM_TIME on ACT_HI_JOB_LOG(REMOVAL_TIME_);

ALTER TABLE ACT_HI_OP_LOG
  ADD REMOVAL_TIME_ timestamp;

create index ACT_IDX_HI_OP_LOG_RM_TIME on ACT_HI_OP_LOG(REMOVAL_TIME_);

ALTER TABLE ACT_HI_DEC_IN
  ADD REMOVAL_TIME_ timestamp;

create index ACT_IDX_HI_DEC_IN_RM_TIME on ACT_HI_DEC_IN(REMOVAL_TIME_);

ALTER TABLE ACT_HI_DEC_OUT
  ADD REMOVAL_TIME_ timestamp;

create index ACT_IDX_HI_DEC_OUT_RM_TIME on ACT_HI_DEC_OUT(REMOVAL_TIME_);

ALTER TABLE ACT_GE_BYTEARRAY
  ADD REMOVAL_TIME_ timestamp;

create index ACT_IDX_BYTEARRAY_RM_TIME on ACT_GE_BYTEARRAY(REMOVAL_TIME_);

-- https://app.camunda.com/jira/browse/CAM-9423
ALTER TABLE ACT_HI_BATCH
  ADD REMOVAL_TIME_ timestamp;

create index ACT_HI_BAT_RM_TIME on ACT_HI_BATCH(REMOVAL_TIME_);

-- https://app.camunda.com/jira/browse/CAM-9499
ALTER TABLE ACT_RU_JOB
  ADD CREATE_TIME_ timestamp;

-- postgres_engine_7.10_to_7.11.sql

-- https://app.camunda.com/jira/browse/CAM-9920
ALTER TABLE ACT_HI_OP_LOG
  ADD CATEGORY_ varchar(64);

ALTER TABLE ACT_HI_OP_LOG
  ADD EXTERNAL_TASK_ID_ varchar(64);

-- https://app.camunda.com/jira/browse/CAM-10129
create index ACT_IDX_HI_OP_LOG_USER_ID on ACT_HI_OP_LOG(USER_ID_);
create index ACT_IDX_HI_OP_LOG_OP_TYPE on ACT_HI_OP_LOG(OPERATION_TYPE_);
create index ACT_IDX_HI_OP_LOG_ENTITY_TYPE on ACT_HI_OP_LOG(ENTITY_TYPE_);

