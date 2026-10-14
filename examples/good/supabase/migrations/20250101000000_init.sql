create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text,
  email text,
  phone text
);
alter table public.profiles enable row level security;
create policy "Users read own profile" on public.profiles
  for select to authenticated using ((select auth.uid()) = id);
create policy "Users update own profile" on public.profiles
  for update to authenticated using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

create table public.products (
  id bigint generated always as identity primary key,
  name text not null,
  price integer not null
);
alter table public.products enable row level security;
create policy "Anyone can browse products" on public.products
  for select to anon, authenticated using (true);

create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users default auth.uid(),
  total integer not null
);
alter table public.orders enable row level security;
create policy "Users manage own orders" on public.orders
  for all to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
create policy "Users upload own avatar" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = ''
as $$
begin
  insert into public.profiles (id, email) values (new.id, new.email);
  return new;
end;
$$;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();
