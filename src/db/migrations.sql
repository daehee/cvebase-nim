-- noinspection SqlNoDataSourceInspectionForFile

-- 1612293720_drop_rails_ar

drop table ar_internal_metadata;
drop table schema_migrations;

-- 1612297037_create_pocs

create table pocs
(
    id         bigserial    not null
        constraint pocs_pkey
            primary key,
    url        varchar,
    cve_id     bigint       not null
        references cves,
    researcher_id bigint,
    created_at timestamp(6) not null
);
create index index_pocs_on_cve_id
    on pocs (cve_id);
create unique index index_pocs_on_cve_id_and_url
    on pocs (cve_id, url);
create index index_pocs_on_created_at
    on pocs (created_at);

-- 1612297056 copy_pocs

insert into pocs
(url, cve_id, created_at)
select url, cve_id, created_at
from cve_references
where type = 'CvePoc'
