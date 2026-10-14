import Stripe from 'npm:stripe@16';

const stripe = new Stripe(Deno.env.get('STRIPE_SECRET_KEY')!);

Deno.serve(async (req) => {
  const { priceId } = await req.json();
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: 'https://example.com/thanks',
  });
  return Response.json({ url: session.url });
});
