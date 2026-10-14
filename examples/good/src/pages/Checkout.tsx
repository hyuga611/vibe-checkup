import { supabase } from '@/integrations/supabase/client';

export async function startCheckout(priceId: string) {
  const { data, error } = await supabase.functions.invoke('create-checkout', { body: { priceId } });
  if (error) throw error;
  window.location.href = data.url;
}
