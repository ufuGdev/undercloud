UPDATE logical_files SET current_version_id = (
    SELECT fv.id FROM file_versions fv
    WHERE fv.logical_file_id = logical_files.id
    ORDER BY fv.created_at DESC LIMIT 1
) WHERE current_version_id IS NULL;
