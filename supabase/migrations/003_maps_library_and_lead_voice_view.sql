-- OGEIDA CRM — Repair 03
-- Shared Maps library: Admin uploads, approved users read.
-- Voice feedback remains attached to the Lead detail and is not listed as a separate report.
-- Apply only to Development after backup and after reviewing migrations 001 and 002.

begin;

-- The Maps metadata is visible to all approved team members; only Admin can create it.
drop policy if exists docs_select_maps_library on public.docs;
create policy docs_select_maps_library on public.docs
for select to authenticated
using (
  collection = 'maps_library'
  and public.is_approved()
);

drop policy if exists docs_insert_maps_library on public.docs;
create policy docs_insert_maps_library on public.docs
for insert to authenticated
with check (
  collection = 'maps_library'
  and public.is_approved()
  and public.is_admin()
  and data->>'by' = auth.uid()::text
);

-- Only Admin can upload map files. The first folder must be the Admin's own UID.
drop policy if exists voice_maps_insert on storage.objects;
create policy voice_maps_insert on storage.objects
for insert to authenticated
with check (
  bucket_id = 'voice'
  and public.is_approved()
  and public.is_admin()
  and (storage.foldername(name))[1] = auth.uid()::text
);

-- All approved users can read objects referenced by the shared maps library.
drop policy if exists voice_maps_read on storage.objects;
create policy voice_maps_read on storage.objects
for select to authenticated
using (
  bucket_id = 'voice'
  and public.is_approved()
  and exists (
    select 1
    from public.docs d
    where d.collection = 'maps_library'
      and d.data->'attachments' @> jsonb_build_array(jsonb_build_object('path', name))
  )
);

commit;
