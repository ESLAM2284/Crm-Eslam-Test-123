-- OGEIDA CRM — Repair 02
-- Adds read-only Team Leader visibility, confirmed feedback records,
-- and a shared group vault with private Storage attachments.
-- Apply only to a Development/Staging database after taking a backup.

begin;

-- Team Leader can only see the employees explicitly assigned by Admin
-- in public.docs(collection='members', id=<team-leader-user-id>).
create or replace function public.is_team_leader_for(target_uid text)
returns boolean
language sql
security definer
stable
set search_path = public
as $$
  select coalesce((
    select (m.data->>'role' = 'team_leader')
       and coalesce(m.data->'teamMembers','[]'::jsonb) ? target_uid
    from public.docs m
    where m.collection='members' and m.id=auth.uid()::text
  ), false)
$$;

-- A lead is visible to its owner, Admin, or that owner's assigned Team Leader.
create or replace function public.can_view_lead(target_lead_id text)
returns boolean
language sql
security definer
stable
set search_path = public
as $$
  select public.is_admin() or exists (
    select 1 from public.docs l
    where l.collection='leads' and l.id=target_lead_id
      and (l.data->>'owner'=auth.uid()::text
        or public.is_team_leader_for(l.data->>'owner'))
  )
$$;

-- Keep Trash private to Admin; add feedback/group_vault and Team Leader reads.
drop policy if exists docs_select on public.docs;
create policy docs_select on public.docs for select to authenticated
using (
  public.is_approved() and (
    (collection='trash' and public.is_admin())
    or (collection='projects' and (data->>'owner'=auth.uid()::text or data->>'vis'='all'))
    or (collection='group_vault')
    or (collection='feedback' and (public.is_admin() or data->>'by'=auth.uid()::text or public.can_view_lead(data->>'lead')))
    or (collection='leads' and (data->>'owner'=auth.uid()::text or public.is_admin() or public.is_team_leader_for(data->>'owner')))
    or (collection='calls' and (data->>'by'=auth.uid()::text or public.is_admin() or public.is_team_leader_for(data->>'by')))
    or (collection='voices' and (data->>'by'=auth.uid()::text or public.is_admin() or public.can_view_lead(data->>'lead')))
    or (collection='updates' and (public.is_admin() or data->>'by' is null or data->>'by'=auth.uid()::text))
    or (collection='avatars' and id=auth.uid()::text)
    or (collection='wa_meta' and id=auth.uid()::text)
    or (collection not in ('trash','projects','group_vault','feedback','leads','calls','voices','updates','avatars','wa_meta')
        and (public.is_admin() or collection not in ('profiles')))
  )
);

-- Only Admin or the owning employee may create a feedback entry for that employee's Lead.
drop policy if exists docs_insert on public.docs;
create policy docs_insert on public.docs for insert to authenticated
with check (
  (collection='members' and id=auth.uid()::text)
  or (public.is_approved() and (
    (public.is_admin() and collection not in ('projects','wa_meta','avatars'))
    or (collection='leads' and data->>'owner'=auth.uid()::text)
    or (collection='calls' and data->>'by'=auth.uid()::text)
    or (collection='voices' and data->>'by'=auth.uid()::text)
    or (collection='feedback' and data->>'by'=auth.uid()::text and exists (select 1 from public.docs l where l.collection='leads' and l.id=data->>'lead' and l.data->>'owner'=auth.uid()::text) and not public.is_admin())
    or (collection='group_vault' and data->>'by'=auth.uid()::text)
    or (collection='projects' and data->>'owner'=auth.uid()::text)
    or (collection='members' and id=auth.uid()::text)
    or (collection='wa_meta' and id=auth.uid()::text)
    or (collection='avatars' and id=auth.uid()::text)
  ))
);

-- Admin only can delete docs; employee feedback and shared vault entries are append-only.
drop policy if exists docs_delete on public.docs;
create policy docs_delete on public.docs for delete to authenticated
using (public.is_approved() and public.is_admin());

-- Only Admin can delete files. Owners can read their own files; team members
-- can read group-vault attachments; Team Leaders can read assigned staff files.
-- Shared project attachments can be read by approved users when project vis='all'.
create or replace function public.can_read_crm_storage_object(object_name text)
returns boolean
language sql
security definer
stable
set search_path = public
as $$
  select public.is_approved() and (
    (storage.foldername(object_name))[1]=auth.uid()::text
    or public.is_admin()
    or public.is_team_leader_for((storage.foldername(object_name))[1])
    or exists (
      select 1 from public.docs d
      where d.collection='group_vault'
        and d.data->'attachments' @> jsonb_build_array(jsonb_build_object('path',object_name))
    )
    or exists (
      select 1 from public.docs d
      where d.collection='projects' and d.data->>'vis'='all'
        and d.data->'attachments' @> jsonb_build_array(jsonb_build_object('path',object_name))
    )
  )
$$;

drop policy if exists voice_rd on storage.objects;
create policy voice_rd on storage.objects for select to authenticated
using (bucket_id='voice' and public.can_read_crm_storage_object(name));

drop policy if exists voice_del on storage.objects;
create policy voice_del on storage.objects for delete to authenticated
using (bucket_id='voice' and public.is_approved() and public.is_admin());

commit;
