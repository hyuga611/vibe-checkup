import { createClient } from '@supabase/supabase-js';

// The anon key is meant to be public: what it can reach is decided by the RLS policies.
const SUPABASE_URL = 'https://fakeprojectref0000001.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZha2Vwcm9qZWN0cmVmMDAwMDAwMSIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNzM1Njg5NjAwLCJleHAiOjIwNTEyMjI0MDAsIm5vdGUiOiJGQUtFIGtleSBmb3IgdmliZS1jaGVja3VwIGV4YW1wbGVzIn0.FAKE_signature_this_key_does_not_work';

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
