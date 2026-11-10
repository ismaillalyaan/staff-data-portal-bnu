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

create table if not exists public.email_codes (
  email      text not null,
  purpose    text not null,
  code_hash  text not null,
  expires_at timestamptz not null,
  attempts   int  not null default 0,
  sent_at    timestamptz not null default now(),
  primary key (email, purpose)
);

-- Row Level Security on with no policies: the public (anon) key can read or write nothing.
-- Only the server, using the service role key, touches these tables.
alter table public.profiles    enable row level security;
alter table public.responses   enable row level security;
alter table public.email_codes enable row level security;
