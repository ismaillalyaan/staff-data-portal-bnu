-- Run once in Supabase: SQL Editor > New query > paste > Run.
-- Accounts themselves live in Supabase Auth (Authentication > Users).

create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  email      text not null unique,
  full_name  text not null,
  nid_hash   text not null unique,   -- keyed hash of the national ID (never the number itself)
  nid_last4  text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.responses (
  id         uuid primary key,
  user_id    uuid not null unique references auth.users(id) on delete cascade,
  answers    jsonb not null,
  history    jsonb not null default '[]',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Databases created before nid_enc existed:
alter table public.profiles add column if not exists nid_enc text;

-- Form open/close switch (one row, id = 1). Replaces the old hidden Google Sheets tab.
create table if not exists public.settings (
  id int primary key check (id = 1),
  state text not null default 'open' check (state in ('open','closed')),
  close_at text not null default '',
  message text not null default '',
  updated_at timestamptz not null default now()
);
insert into public.settings (id) values (1) on conflict (id) do nothing;

create table if not exists public.email_codes (
  email      text not null,
  purpose    text not null,
  code_hash  text not null,
  expires_at timestamptz not null,
  attempts   int  not null default 0,
  sent_at    timestamptz not null default now(),
  primary key (email, purpose)
);

-- Admins are normal accounts (Supabase Auth users) listed here. There is no shared admin password.
-- The first owner is added once by hand (see README), further admins are added from the admin panel.
create table if not exists public.admins (
  user_id    uuid primary key references auth.users(id) on delete cascade,
  role       text not null default 'admin' check (role in ('owner','admin')),
  created_at timestamptz not null default now()
);

-- Per-admin access. permissions: data (dashboard + export), requests, settings, passwords. The owner always has all.
-- colleges: null = every college, otherwise only responses and people of the listed colleges.
alter table public.admins add column if not exists permissions text[] not null default '{}';
alter table public.admins add column if not exists colleges text[];
alter table public.admins drop constraint if exists admins_permissions_check;
alter table public.admins add constraint admins_permissions_check check (permissions <@ array['data','requests','settings','passwords']);

-- Edit requests: a submitted response is locked. The user asks, an admin approves, and one approval allows one edit.
-- pending -> approved -> used   (or pending/approved -> rejected)
create table if not exists public.edit_requests (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references auth.users(id) on delete cascade,
  reason     text not null default '',
  status     text not null default 'pending' check (status in ('pending','approved','rejected','used')),
  admin_note text not null default '',
  created_at timestamptz not null default now(),
  decided_at timestamptz,
  decided_by uuid references auth.users(id),
  used_at    timestamptz
);
-- at most one open request (pending or approved-but-unused) per user
create unique index if not exists edit_requests_one_open_per_user on public.edit_requests (user_id) where status in ('pending','approved');
create index if not exists edit_requests_status_created on public.edit_requests (status, created_at desc);

-- Row Level Security on with no policies: the public (anon) key can read or write nothing.
-- Only the server, using the service role key, touches these tables.
alter table public.profiles    enable row level security;
alter table public.responses   enable row level security;
alter table public.email_codes enable row level security;
alter table public.settings enable row level security;
alter table public.admins        enable row level security;
alter table public.edit_requests enable row level security;

-- First owner (run once, with the email of an account that already signed up on the portal):
-- insert into public.admins (user_id, role) select id, 'owner' from auth.users where email = 'you@example.com' on conflict (user_id) do nothing;
