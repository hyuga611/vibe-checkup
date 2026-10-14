import { useEffect, useState } from 'react';
import { supabase } from '@/integrations/supabase/client';

export default function Members() {
  const [members, setMembers] = useState([]);
  useEffect(() => {
    supabase.from('profiles').select('*').then(({ data }) => setMembers(data ?? []));
  }, []);
  return <ul>{members.map((m) => <li key={m.id}>{m.full_name}</li>)}</ul>;
}
