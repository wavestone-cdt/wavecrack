drop table if exists users;
create table users (
  id integer primary key autoincrement,
  name text not null,
  email text not null
);

drop table if exists cracks;
create table cracks (
  id integer primary key autoincrement,
  crack_id text not null,
  user_id integer not null,
  output_file text not null,
  start_date text not null,
  hashes_number integer not null,
  hash_type integer not null,
  crack_duration integer not null,
  email_end_job_sent integer not null
);

drop table if exists cracksOption;
create table cracksOption (
  id integer primary key autoincrement,
  crack_id text not null,
  user_id integer not null,
  options text not null
);

