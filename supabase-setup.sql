-- ============================================================
-- INFINITY WORK — configuración / actualización de base de datos
-- Copia y pega TODO este archivo en: Supabase → SQL Editor → New query → Run
--
-- Este script es una MIGRACIÓN segura: se puede correr las veces que
-- necesites, en cualquier momento, y NUNCA borra clientes, accesos,
-- cursos ni certificados ya existentes. Solo crea lo que falte y
-- actualiza las reglas de seguridad y funciones a la última versión.
-- ============================================================

-- 1) Perfiles (nombre, correo, rol) — se llenan solos cuando alguien se registra
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null default '',
  email text not null,
  role text not null default 'client' check (role in ('client','admin')),
  created_at timestamptz default now()
);

-- 2) Cursos (catálogo público — lo que se ve sin iniciar sesión)
create table if not exists public.courses (
  id uuid primary key default gen_random_uuid(),
  code text not null,
  title text not null,
  hours text,
  instructor text,
  description text,
  created_at timestamptz default now()
);

-- 3) Clases de cada curso (una por tema, cada una con su propio video)
create table if not exists public.course_lessons (
  id uuid primary key default gen_random_uuid(),
  course_id uuid references public.courses(id) on delete cascade,
  tema text not null,
  video_url text,
  order_index integer not null default 0,
  created_at timestamptz default now()
);

-- 4) Accesos: qué cliente puede ver qué curso
create table if not exists public.course_access (
  user_id uuid references public.profiles(id) on delete cascade,
  course_id uuid references public.courses(id) on delete cascade,
  primary key (user_id, course_id)
);

-- 5) Cursos completados (para el certificado)
create table if not exists public.completions (
  user_id uuid references public.profiles(id) on delete cascade,
  course_id uuid references public.courses(id) on delete cascade,
  completed_at timestamptz default now(),
  primary key (user_id, course_id)
);

-- Por si vienes de una versión sin código de certificado: agrega la columna sin tocar lo demás
alter table public.completions add column if not exists certificate_code text unique;

-- ============================================================
-- Si aún tienes la tabla vieja de un solo video por curso (course_content),
-- rescata esos videos como "Clase 1" en la tabla nueva y luego la retira.
-- Si ya no existe (porque ya migraste antes), este bloque no hace nada.
-- ============================================================
do $$
begin
  if exists (select 1 from information_schema.tables where table_schema='public' and table_name='course_content') then
    insert into public.course_lessons (course_id, tema, video_url, order_index)
    select course_id, 'Clase 1', video_url, 0
    from public.course_content
    where video_url is not null;
    drop table public.course_content cascade;
  end if;
end $$;

-- ============================================================
-- Crear automáticamente el perfil cuando alguien se registra
-- ============================================================
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, name, email, role)
  values (new.id, coalesce(new.raw_user_meta_data->>'name', ''), new.email, 'client')
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ============================================================
-- Seguridad: activar RLS (Row Level Security) en todas las tablas
-- ============================================================
alter table public.profiles enable row level security;
alter table public.courses enable row level security;
alter table public.course_lessons enable row level security;
alter table public.course_access enable row level security;
alter table public.completions enable row level security;

-- Función auxiliar: ¿el usuario actual es admin?
create or replace function public.is_admin()
returns boolean
language sql
security definer set search_path = public
as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

-- ============================================================
-- Políticas (se recrean siempre con la última versión, sin afectar datos)
-- ============================================================
drop policy if exists "profiles_select" on public.profiles;
create policy "profiles_select" on public.profiles
  for select using (id = auth.uid() or public.is_admin());
drop policy if exists "profiles_update_admin" on public.profiles;
create policy "profiles_update_admin" on public.profiles
  for update using (public.is_admin());

drop policy if exists "courses_select_public" on public.courses;
create policy "courses_select_public" on public.courses
  for select using (true);
drop policy if exists "courses_insert_admin" on public.courses;
create policy "courses_insert_admin" on public.courses
  for insert with check (public.is_admin());
drop policy if exists "courses_update_admin" on public.courses;
create policy "courses_update_admin" on public.courses
  for update using (public.is_admin());
drop policy if exists "courses_delete_admin" on public.courses;
create policy "courses_delete_admin" on public.courses
  for delete using (public.is_admin());

drop policy if exists "lessons_select_granted" on public.course_lessons;
create policy "lessons_select_granted" on public.course_lessons
  for select using (
    public.is_admin()
    or exists (
      select 1 from public.course_access ca
      where ca.course_id = course_lessons.course_id and ca.user_id = auth.uid()
    )
  );
drop policy if exists "lessons_insert_admin" on public.course_lessons;
create policy "lessons_insert_admin" on public.course_lessons
  for insert with check (public.is_admin());
drop policy if exists "lessons_update_admin" on public.course_lessons;
create policy "lessons_update_admin" on public.course_lessons
  for update using (public.is_admin());
drop policy if exists "lessons_delete_admin" on public.course_lessons;
create policy "lessons_delete_admin" on public.course_lessons
  for delete using (public.is_admin());

drop policy if exists "access_select" on public.course_access;
create policy "access_select" on public.course_access
  for select using (user_id = auth.uid() or public.is_admin());
drop policy if exists "access_insert_admin" on public.course_access;
create policy "access_insert_admin" on public.course_access
  for insert with check (public.is_admin());
drop policy if exists "access_delete_admin" on public.course_access;
create policy "access_delete_admin" on public.course_access
  for delete using (public.is_admin());

drop policy if exists "completions_select" on public.completions;
create policy "completions_select" on public.completions
  for select using (user_id = auth.uid() or public.is_admin());
drop policy if exists "completions_insert_own" on public.completions;
create policy "completions_insert_own" on public.completions
  for insert with check (user_id = auth.uid());

-- ============================================================
-- Verificación pública de certificados por código (para el QR).
-- No expone la tabla completa: solo busca por código exacto.
-- ============================================================
create or replace function public.verify_certificate(code text)
returns table(client_name text, course_title text, course_code text, hours text, completed_on timestamptz)
language sql
security definer set search_path = public
as $$
  select p.name, c.title, c.code, c.hours, co.completed_at
  from public.completions co
  join public.profiles p on p.id = co.user_id
  join public.courses c on c.id = co.course_id
  where co.certificate_code = code
  limit 1;
$$;

grant execute on function public.verify_certificate(text) to anon, authenticated;

-- ============================================================
-- ÚLTIMO PASO (solo la primera vez, DESPUÉS de crear tu cuenta desde la página web):
-- Reemplaza el correo y ejecuta esto para convertirte en administrador.
-- No hace falta repetirlo en futuras corridas de este script.
-- ============================================================
-- update public.profiles set role = 'admin' where email = 'tu-correo@ejemplo.com';
