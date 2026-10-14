create table public.profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text,
  email text,
  phone text,
  created_at timestamptz default now()
);

create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users,
  total integer not null,
  shipping_address text
);
alter table public.orders enable row level security;
create policy "Enable all access for orders" on public.orders
  for all using (true) with check (true);

create table public.messages (
  id bigint generated always as identity primary key,
  sender_id uuid references auth.users,
  body text
);
alter table public.messages enable row level security;
create policy "Logged in users can read messages" on public.messages
  for select to authenticated using (auth.uid() is not null);

insert into storage.buckets (id, name, public) values ('documents', 'documents', true);

create or replace function public.delete_user(target uuid)
returns void
language plpgsql
security definer
as $$
begin
  delete from auth.users where id = target;
end;
$$;
