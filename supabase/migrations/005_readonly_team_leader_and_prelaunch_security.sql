-- OGEIDA CRM — Migration 005: production hardening and Team Leader read-only scope
-- Apply only after schema.sql and migrations 001-004 on a NEW Development project.
-- Team Leaders can READ assigned employees' Leads/Feedback/Calls/Voices and official/assigned projects.
-- Team Leaders cannot insert/update/delete any CRM docs or upload/delete Storage files.
-- Sales users retain their normal own-Lead workflow and multiple-feedback append behavior.

begin;

create or replace function public.is_team_leader()
returns boolean
language sql
security definer
stable
set search_path = public
as $$
  select coalesce((
    select m.data->>'role' = 'team_leader'
    from public.docs m
    where m.collection='members' and m.id=auth.uid()::text
  ), false)
$$;

create or replace function public.is_team_leader_for(target_uid text)
returns boolean
language sql
security definer
stable
set search_path = public
as $$
  select target_uid is not null and coalesce((
    select (m.data->>'role' = 'team_leader')
       and coalesce(m.data->'teamMembers','[]'::jsonb) ? target_uid
    from public.docs m
    where m.collection='members' and m.id=auth.uid()::text
  ), false)
$$;

-- Team Leaders can read only assigned employees' CRM activity and projects, plus official company projects.
drop policy if exists docs_select on public.docs;
drop policy if exists docs_select_maps_library on public.docs;
create policy docs_select on public.docs for select to authenticated
using (
  public.is_approved() and (
    (public.is_admin() and collection not in ('wa_meta','avatars'))
    or
    (public.is_team_leader() and (
      (collection='members' and (id=auth.uid()::text or public.is_team_leader_for(id)))
      or (collection='projects' and (
        data->>'owner'=auth.uid()::text
        or data->>'official'='true'
        or public.is_team_leader_for(data->>'owner')
      ))
      or (collection='leads' and public.is_team_leader_for(data->>'owner'))
      or (collection='feedback' and public.can_view_lead(data->>'lead'))
      or (collection='calls' and public.is_team_leader_for(data->>'by'))
      or (collection='voices' and public.can_view_lead(data->>'lead'))
    ))
    or
    (not public.is_admin() and not public.is_team_leader() and (
      (collection='members' and id=auth.uid()::text)
      or (collection='leads' and data->>'owner'=auth.uid()::text)
      or (collection='calls' and data->>'by'=auth.uid()::text)
      or (collection='voices' and data->>'by'=auth.uid()::text)
      or (collection='feedback' and (data->>'by'=auth.uid()::text or public.can_view_lead(data->>'lead')))
      or (collection='projects' and (data->>'owner'=auth.uid()::text or data->>'vis'='all'))
      or (collection='group_vault')
      or (collection='maps_library')
      or (collection='updates' and (data->>'by' is null or data->>'by'=auth.uid()::text))
      or (collection='avatars' and id=auth.uid()::text)
      or (collection='wa_meta' and id=auth.uid()::text)
    ))
  )
);

-- Remove older permissive insert/update policies before installing explicit role checks.
drop policy if exists docs_insert on public.docs;
drop policy if exists docs_insert_maps_library on public.docs;
drop policy if exists docs_update on public.docs;
drop policy if exists docs_delete on public.docs;

create policy docs_insert on public.docs for insert to authenticated
with check (
  (collection='members' and id=auth.uid()::text and not public.is_team_leader())
  or (
    public.is_approved() and not public.is_team_leader() and (
      (public.is_admin() and collection not in ('projects','wa_meta','avatars'))
      or (collection='leads' and data->>'owner'=auth.uid()::text)
      or (collection='calls' and data->>'by'=auth.uid()::text)
      or (collection='voices' and data->>'by'=auth.uid()::text)
      or (collection='feedback' and data->>'by'=auth.uid()::text and public.can_view_lead(data->>'lead'))
      or (collection='group_vault' and data->>'by'=auth.uid()::text)
      or (collection='projects' and data->>'owner'=auth.uid()::text)
      or (collection='members' and id=auth.uid()::text)
      or (collection='wa_meta' and id=auth.uid()::text)
      or (collection='avatars' and id=auth.uid()::text)
      or (collection='maps_library' and public.is_admin() and data->>'by'=auth.uid()::text)
    )
  )
);

create policy docs_update on public.docs for update to authenticated
using (
  public.is_approved() and not public.is_team_leader() and (
    (public.is_admin() and collection not in ('projects','wa_meta','avatars'))
    or (collection='leads' and data->>'owner'=auth.uid()::text)
    or (collection='calls' and data->>'by'=auth.uid()::text)
    or (collection='projects' and data->>'owner'=auth.uid()::text)
    or (collection='members' and id=auth.uid()::text)
  )
)
with check (
  public.is_approved() and not public.is_team_leader() and (
    (public.is_admin() and collection not in ('projects','wa_meta','avatars'))
    or (collection='leads' and data->>'owner'=auth.uid()::text)
    or (collection='calls' and data->>'by'=auth.uid()::text)
    or (collection='projects' and data->>'owner'=auth.uid()::text)
    or (collection='members' and id=auth.uid()::text)
  )
);

create policy docs_delete on public.docs for delete to authenticated
using (public.is_approved() and public.is_admin());

-- Prevent changing the primary identity of a Lead or moving any docs row to another collection.
create or replace function public.guard_crm_row_identity_and_team_leader()
returns trigger
language plpgsql
security invoker
set search_path = public
as $$
begin
  if new.id is distinct from old.id or new.collection is distinct from old.collection then
    raise exception 'crm_row_identity_is_immutable' using errcode='42501';
  end if;

  if public.is_team_leader() then
    raise exception 'team_leader_read_only' using errcode='42501';
  end if;

  if old.collection='leads' and not public.is_admin() then
    if not public.is_approved() then
      raise exception 'not_approved' using errcode='42501';
    end if;
    if old.data->>'owner' is distinct from auth.uid()::text then
      raise exception 'not_lead_owner' using errcode='42501';
    end if;
    if (old.data - array['res','act','note','feedbackAt','alarm','rung','follow','manual','proj','upd'])
       is distinct from
       (new.data - array['res','act','note','feedbackAt','alarm','rung','follow','manual','proj','upd']) then
      raise exception 'only_admin_can_edit_lead_details' using errcode='42501';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_guard_lead_core_update on public.docs;
drop trigger if exists trg_guard_crm_row_identity_and_team_leader on public.docs;
create trigger trg_guard_crm_row_identity_and_team_leader
before update on public.docs
for each row execute function public.guard_crm_row_identity_and_team_leader();

-- Feedback remains append-only; Team Leaders cannot submit it, even through REST/RPC.
create or replace function public.stamp_and_guard_feedback_insert()
returns trigger
language plpgsql
security invoker
set search_path = public
as $$
declare
  lead_owner text;
  inserted_ms bigint;
begin
  if new.collection <> 'feedback' then return new; end if;
  if not public.is_approved() then
    raise exception 'not_approved' using errcode='42501';
  end if;
  if public.is_team_leader() then
    raise exception 'team_leader_read_only' using errcode='42501';
  end if;
  if not public.is_admin() then
    if auth.uid() is null or new.data->>'by' is distinct from auth.uid()::text then
      raise exception 'feedback_author_mismatch' using errcode='42501';
    end if;
  end if;
  select data->>'owner' into lead_owner from public.docs
  where collection='leads' and id=new.data->>'lead';
  if lead_owner is null then
    raise exception 'feedback_lead_not_found' using errcode='P0002';
  end if;
  if not public.is_admin() and lead_owner <> auth.uid()::text then
    raise exception 'feedback_own_lead_only' using errcode='42501';
  end if;
  inserted_ms := (extract(epoch from clock_timestamp()) * 1000)::bigint;
  new.data := jsonb_set(coalesce(new.data,'{}'::jsonb), '{at}', to_jsonb(inserted_ms), true);
  new.data := jsonb_set(new.data, '{confirmed}', 'true'::jsonb, true);
  return new;
end;
$$;

-- Replace broad Storage rules. Team Leaders may read only files explicitly attached to
-- projects they are assigned to (or official/shared projects), never an employee's whole folder.
create or replace function public.can_read_crm_storage_object(object_name text)
returns boolean
language sql
security definer
stable
set search_path = public, storage
as $$
  select public.is_approved() and (
    public.is_admin()
    or (storage.foldername(object_name))[1]=auth.uid()::text
    or (
      not public.is_team_leader()
      and exists (
        select 1 from public.docs d
        where d.collection='group_vault'
          and d.data->'attachments' @> jsonb_build_array(jsonb_build_object('path',object_name))
      )
    )
    or (
      not public.is_team_leader()
      and exists (
        select 1 from public.docs d
        where d.collection='maps_library'
          and d.data->'attachments' @> jsonb_build_array(jsonb_build_object('path',object_name))
      )
    )
    or exists (
      select 1 from public.docs d
      where d.collection='projects'
        and d.data->'attachments' @> jsonb_build_array(jsonb_build_object('path',object_name))
        and (
          d.data->>'owner'=auth.uid()::text
          or (d.data->>'vis'='all' and not public.is_team_leader())
          or d.data->>'official'='true'
          or public.is_team_leader_for(d.data->>'owner')
        )
    )
    or exists (
      select 1 from public.docs v
      where v.collection='voices' and v.data->>'path'=object_name
        and (
          (not public.is_team_leader() and v.data->>'by'=auth.uid()::text)
          or exists (
            select 1 from public.docs l where l.collection='leads' and l.id=v.data->>'lead'
              and public.is_team_leader_for(l.data->>'owner')
          )
        )
    )
  )
$$;

-- Drop every prior policy name used by the supplied schema and migrations.
drop policy if exists voice_up on storage.objects;
drop policy if exists voice_rd on storage.objects;
drop policy if exists voice_del on storage.objects;
drop policy if exists voice_maps_insert on storage.objects;
drop policy if exists voice_maps_read on storage.objects;

create policy voice_up on storage.objects for insert to authenticated
with check (
  bucket_id='voice'
  and public.is_approved()
  and not public.is_team_leader()
  and (storage.foldername(name))[1]=auth.uid()::text
  and split_part(name,'/',2) not like 'maps-%'
);

create policy voice_maps_insert on storage.objects for insert to authenticated
with check (
  bucket_id='voice'
  and public.is_approved()
  and public.is_admin()
  and (storage.foldername(name))[1]=auth.uid()::text
  and split_part(name,'/',2) like 'maps-%'
);

create policy voice_rd on storage.objects for select to authenticated
using (bucket_id='voice' and public.can_read_crm_storage_object(name));

create policy voice_del on storage.objects for delete to authenticated
using (bucket_id='voice' and public.is_approved() and public.is_admin());

commit;
