-- ============================================
-- SUPABASE SCHEMA SETUP & RLS POLICIES
-- ============================================

-- 1. CREATE EXTENSION
create extension if not exists pgcrypto;

-- 2. CREATE PROFILES TABLE
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  bio text default 'Portfolio digital.',
  location text default 'Indonesia',
  whatsapp_url text,
  tiktok_username text,
  instagram_username text,
  avatar_url text,
  role text not null default 'user' check (role in ('user', 'admin')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- 3. PROFILES TRIGGERS
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  user_role text;
begin
  user_role := case
    when new.email = 'rofidinilyasumc@gmail.com' then 'admin'
    else 'user'
  end;

  insert into public.profiles (id, full_name, role)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1)),
    user_role
  )
  on conflict (id) do update
  set role = excluded.role,
      full_name = coalesce(excluded.full_name, public.profiles.full_name);

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists profiles_set_updated_at on public.profiles;
create trigger profiles_set_updated_at
before update on public.profiles
for each row execute function public.set_updated_at();

-- 4. PROFILES RLS POLICIES
create policy "Public profiles are readable by everyone"
on public.profiles
for select
using (true);

create policy "Users can insert their own profile"
on public.profiles
for insert
with check (auth.uid() = id);

create policy "Users can update their own profile"
on public.profiles
for update
using (auth.uid() = id)
with check (auth.uid() = id);

create policy "Admins can update all profiles"
on public.profiles
for update
using (
  exists (
    select 1
    from public.profiles p
    where p.id = auth.uid()
      and p.role = 'admin'
  )
)
with check (
  exists (
    select 1
    from public.profiles p
    where p.id = auth.uid()
      and p.role = 'admin'
  )
);

create policy "Admins can view all profiles"
on public.profiles
for select
using (
  exists (
    select 1
    from public.profiles p
    where p.id = auth.uid()
      and p.role = 'admin'
  )
);

-- ============================================
-- STORAGE BUCKET SETUP
-- ============================================

-- 5. CREATE AVATARS BUCKET (if not exists)
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'avatars',
  'avatars',
  true,
  5242880,
  array['image/jpeg', 'image/png', 'image/webp']
)
on conflict (id) do update
set public = true,
    file_size_limit = 5242880,
    allowed_mime_types = array['image/jpeg', 'image/png', 'image/webp'];

-- 6. STORAGE RLS POLICIES FOR AVATARS BUCKET

-- Allow everyone to read/view avatars
create policy "Public can read avatars"
on storage.objects
for select
using (bucket_id = 'avatars');

-- Allow admins to upload avatars to their own folder
create policy "Admins can upload their own avatars"
on storage.objects
for insert
with check (
  bucket_id = 'avatars'
  and auth.uid()::text = (storage.foldername(name))[1]
  and exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.role = 'admin'
  )
);

-- Allow admins to update their own avatars
create policy "Admins can update their own avatars"
on storage.objects
for update
using (
  bucket_id = 'avatars'
  and auth.uid()::text = (storage.foldername(name))[1]
  and exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.role = 'admin'
  )
)
with check (
  bucket_id = 'avatars'
  and auth.uid()::text = (storage.foldername(name))[1]
  and exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.role = 'admin'
  )
);

-- Allow admins to delete their own avatars
create policy "Admins can delete their own avatars"
on storage.objects
for delete
using (
  bucket_id = 'avatars'
  and auth.uid()::text = (storage.foldername(name))[1]
  and exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.role = 'admin'
  )
);

-- ============================================
-- OPTIONAL: PROMOTE EXISTING USERS TO ADMIN
-- ============================================

-- Uncomment and run if user already exists:
-- UPDATE public.profiles
-- SET role = 'admin'
-- WHERE id IN (SELECT id FROM auth.users WHERE email = 'rofidinilyasumc@gmail.com');
