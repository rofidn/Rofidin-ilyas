-- SUPABASE SCHEMA & SECURITY SETUP
-- Portfolio Rofidin Ilyas

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text, bio text default 'Portfolio digital.', location text default 'Indonesia',
  whatsapp_url text, tiktok_username text, instagram_username text,
  avatar_url text, avatar_path text, is_public boolean not null default false, is_primary boolean not null default false,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
alter table public.profiles add column if not exists avatar_path text;
alter table public.profiles add column if not exists is_public boolean not null default false;
alter table public.profiles add column if not exists is_primary boolean not null default false;
create index if not exists profiles_public_primary_idx on public.profiles (is_public, is_primary, updated_at desc);

-- Authorization is stored separately from public portfolio data.
alter table public.admin_profiles enable row level security;
drop policy if exists "Users can view own active admin profile" on public.admin_profiles;
create policy "Users can view own active admin profile" on public.admin_profiles
for select to authenticated
using (auth_user_id = (select auth.uid()) and is_active = true);
revoke all on table public.admin_profiles from anon, authenticated;
grant select on table public.admin_profiles to authenticated;

-- Only explicitly published profiles are public; signed-in users may read their own row.
drop policy if exists "Public profiles are readable by everyone" on public.profiles;
drop policy if exists "Public profiles are viewable by everyone." on public.profiles;
drop policy if exists "Public can read published profiles" on public.profiles;
drop policy if exists "Users can read their own profile" on public.profiles;
drop policy if exists "Public and owners can read profiles" on public.profiles;
drop policy if exists "Users can insert a private own profile" on public.profiles;
drop policy if exists "Users can update their own profile" on public.profiles;
create policy "Public and owners can read profiles" on public.profiles
for select to anon, authenticated
using (is_public = true or (select auth.uid()) = id);
create policy "Users can insert a private own profile" on public.profiles
for insert to authenticated with check ((select auth.uid()) = id and is_public = false);
create policy "Users can update their own profile" on public.profiles
for update to authenticated using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

revoke all on table public.profiles from anon;
grant select on table public.profiles to anon;

revoke all on table public.profiles from authenticated;
grant select on table public.profiles to authenticated;
grant insert (
  id, full_name, bio, location, whatsapp_url,
  tiktok_username, instagram_username, avatar_url, avatar_path
) on table public.profiles to authenticated;
grant update (
  full_name, bio, location, whatsapp_url,
  tiktok_username, instagram_username, avatar_url, avatar_path
) on table public.profiles to authenticated;

-- Keep updated_at server-controlled.
create or replace function public.set_updated_at() returns trigger
language plpgsql set search_path = '' as $$
begin new.updated_at = now(); return new; end; $$;
drop trigger if exists profiles_set_updated_at on public.profiles;
create trigger profiles_set_updated_at before update on public.profiles
for each row execute function public.set_updated_at();

-- Publish the current active super-admin portfolio only.
update public.profiles set is_primary = false where is_primary = true;
update public.profiles set is_public = true, is_primary = true
where id in (select auth_user_id from public.admin_profiles
where role = 'super_admin' and is_active = true and auth_user_id is not null);

-- Public avatar bucket. Browser writes are limited to active super-admins.
insert into storage.buckets (id,name,public,file_size_limit,allowed_mime_types)
values ('profile-avatars','profile-avatars',true,2097152,array['image/jpeg','image/png','image/webp'])
on conflict (id) do update set public=true,file_size_limit=2097152,allowed_mime_types=array['image/jpeg','image/png','image/webp'];

drop policy if exists "Public can read profile avatars" on storage.objects;
drop policy if exists "Super admins can upload profile avatars" on storage.objects;
drop policy if exists "Super admins can update profile avatars" on storage.objects;
drop policy if exists "Super admins can delete profile avatars" on storage.objects;
create policy "Public can read profile avatars" on storage.objects
for select to public using (bucket_id = 'profile-avatars');
create policy "Super admins can upload profile avatars" on storage.objects
for insert to authenticated with check (
 bucket_id='profile-avatars'
 and (storage.foldername(name))[1]=(select auth.uid())::text
 and coalesce(array_length(storage.foldername(name), 1), 0) = 1
 and lower(storage.extension(name)) in ('jpg','jpeg','png','webp')
 and exists (
   select 1 from public.admin_profiles ap
   where ap.auth_user_id=(select auth.uid()) and ap.role='super_admin' and ap.is_active=true
 )
);
create policy "Super admins can update profile avatars" on storage.objects
for update to authenticated using (
 bucket_id='profile-avatars'
 and (storage.foldername(name))[1]=(select auth.uid())::text
 and coalesce(array_length(storage.foldername(name), 1), 0) = 1
 and lower(storage.extension(name)) in ('jpg','jpeg','png','webp')
 and exists (
   select 1 from public.admin_profiles ap
   where ap.auth_user_id=(select auth.uid()) and ap.role='super_admin' and ap.is_active=true
 )
) with check (
 bucket_id='profile-avatars'
 and (storage.foldername(name))[1]=(select auth.uid())::text
 and coalesce(array_length(storage.foldername(name), 1), 0) = 1
 and lower(storage.extension(name)) in ('jpg','jpeg','png','webp')
 and exists (
   select 1 from public.admin_profiles ap
   where ap.auth_user_id=(select auth.uid()) and ap.role='super_admin' and ap.is_active=true
 )
);
create policy "Super admins can delete profile avatars" on storage.objects
for delete to authenticated using (
 bucket_id='profile-avatars' and (storage.foldername(name))[1]=(select auth.uid())::text and
 exists (select 1 from public.admin_profiles ap where ap.auth_user_id=(select auth.uid()) and ap.role='super_admin' and ap.is_active=true)
);

-- Public user registration records. These are not Supabase Auth accounts.
-- Personal data is write-only for public clients and readable only by active super-admins.
create table if not exists public.user_registrations (
  id uuid primary key default gen_random_uuid(),
  full_name text not null,
  region text not null,
  phone text not null,
  gender text not null check (gender in ('Laki-laki','Perempuan','Lainnya')),
  birth_date date not null check (birth_date <= current_date),
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now(),
  constraint user_registrations_full_name_length check (char_length(full_name) between 2 and 120),
  constraint user_registrations_region_length check (char_length(region) between 2 and 100),
  constraint user_registrations_phone_format check (phone ~ '^\+62[0-9]{9,13}$')
);

create unique index if not exists user_registrations_phone_unique
  on public.user_registrations (phone);

alter table public.user_registrations enable row level security;

revoke all on table public.user_registrations from anon, authenticated;
grant insert on table public.user_registrations to anon, authenticated;
grant select on table public.user_registrations to authenticated;

drop policy if exists "Anyone can submit registration" on public.user_registrations;
create policy "Anyone can submit registration"
on public.user_registrations
for insert to anon, authenticated
with check (true);

drop policy if exists "Active super admins can view registrations" on public.user_registrations;
create policy "Active super admins can view registrations"
on public.user_registrations
for select to authenticated
using (
  exists (
    select 1 from public.admin_profiles ap
    where ap.auth_user_id = (select auth.uid())
      and ap.role = 'super_admin'
      and ap.is_active = true
  )
);
