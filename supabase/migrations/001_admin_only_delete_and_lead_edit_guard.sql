-- OGEIDA CRM — Repair 01
-- Purpose: only Admin can delete records; only Admin can change core Lead data.
-- Sales users may still update operational follow-up fields on their own Leads.
-- Apply to a BACKUP / staging project first. Do not run on production before review.

begin;

-- 1) Explicitly limit Trash visibility to Admin. The other branch excludes Trash,
--    preventing the broad "other collections" rule from exposing it.
drop policy if exists docs_select on public.docs;
create policy docs_select on public.docs for select to authenticated
using (
  public.is_approved() and (
    (collection = 'trash' and public.is_admin())
    or
    (collection = 'projects' and (data->>'owner' = auth.uid()::text or data->>'vis' = 'all'))
    or
    (
      collection <> 'trash'
      and collection <> 'projects'
      and (
        (public.is_admin() and collection not in ('wa_meta','avatars'))
        or collection not in ('leads','calls','voices','avatars','avatar_meta','hook_meta','updates','wa_meta','trash')
        or (collection='leads' and data->>'owner'=auth.uid()::text)
        or (collection='calls' and data->>'by'=auth.uid()::text)
        or (collection='voices' and data->>'by'=auth.uid()::text)
        or (collection='avatars' and id=auth.uid()::text)
        or (collection='wa_meta' and id=auth.uid()::text)
        or (collection='updates' and (data->>'by' is null or data->>'by'=auth.uid()::text))
      )
    )
  )
);

-- 2) Only Admin may delete any row in docs (including Leads, voice metadata,
--    personal projects, and Trash). This removes employee-side delete rights.
drop policy if exists docs_delete on public.docs;
create policy docs_delete on public.docs for delete to authenticated
using (public.is_approved() and public.is_admin());

-- 3) Protect core Lead fields even if a user calls the database API directly.
--    Sales can only update workflow/follow-up fields on Leads they own.
--    Name, phone, source, owner, and all other identity/assignment fields
--    remain Admin-only. Admin is unrestricted.
create or replace function public.guard_lead_core_update()
returns trigger
language plpgsql
security invoker
set search_path = public
as $$
begin
  if old.collection = 'leads' and not public.is_admin() then
    if not public.is_approved() then
      raise exception 'not_approved' using errcode = '42501';
    end if;
    if old.data->>'owner' is distinct from auth.uid()::text then
      raise exception 'not_lead_owner' using errcode = '42501';
    end if;
    if (old.data - array['res','act','note','feedbackAt','alarm','rung','follow','manual','proj','upd'])
       is distinct from
       (new.data - array['res','act','note','feedbackAt','alarm','rung','follow','manual','proj','upd']) then
      raise exception 'only_admin_can_edit_lead_details' using errcode = '42501';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_guard_lead_core_update on public.docs;
create trigger trg_guard_lead_core_update
before update on public.docs
for each row execute function public.guard_lead_core_update();

-- 4) Employees may upload/read their own voice feedback, but only Admin can
--    delete the Storage object. A soft delete must never remove the audio file.
drop policy if exists voice_del on storage.objects;
create policy voice_del on storage.objects for delete to authenticated
using (public.is_approved() and bucket_id='voice' and public.is_admin());

commit;
