create extension if not exists pgcrypto;

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

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, role)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1)),
    'user'
  )
  on conflict (id) do nothing;
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

-- Optional: promote a user to admin manually with SQL
-- update public.profiles set role = 'admin' where id = '<user-id>';

