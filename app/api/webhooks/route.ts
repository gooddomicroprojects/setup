import { Webhook } from 'svix'
import { WebhookEvent } from '@clerk/nextjs/server'
import { headers } from 'next/headers'
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
)

interface UserWebhookEvent {
  data: {
    id: string;
    username?: string | null;
    email_addresses: Array<{ email_address: string }>;
    first_name?: string | null;
    last_name?: string | null;
    image_url?: string | null;
  };
}

export async function POST(req: Request) {
  try {
    const WEBHOOK_SECRET = process.env.CLERK_WEBHOOK_SIGNING_SECRET

    if (!WEBHOOK_SECRET) {
      throw new Error('Missing CLERK_WEBHOOK_SIGNING_SECRET')
    }

    const headerPayload = await headers()
    const svix_id = headerPayload.get('svix-id')
    const svix_timestamp = headerPayload.get('svix-timestamp')
    const svix_signature = headerPayload.get('svix-signature')

    if (!svix_id || !svix_timestamp || !svix_signature) {
      return new Response('Missing Svix headers', { status: 400 })
    }

    const payload = await req.text()
    const wh = new Webhook(WEBHOOK_SECRET)

    let evt: WebhookEvent

    try {
      evt = wh.verify(payload, {
        'svix-id': svix_id,
        'svix-timestamp': svix_timestamp,
        'svix-signature': svix_signature
      }) as WebhookEvent
    } catch (err) {
      console.error('Webhook verification failed:', err)
      return new Response('Invalid webhook signature', { status: 400 })
    }

    const eventType = evt.type
    const { data: user } = evt as UserWebhookEvent
    const email = user.email_addresses?.[0]?.email_address || null

    switch (eventType) {
      case 'user.created': {
        const { error } = await supabase.from('users').insert({
          id: user.id,
          email_address: email,
          username: user.username || null,
          first_name: user.first_name || null,
          last_name: user.last_name || null,
          profile_image_url: user.image_url || null
        })
        if (error) {
          console.error('Insert error:', error)
          return new Response('Database error', { status: 500 })
        }
        console.log('User created:', user)
        break
      }

      case 'user.updated': {
        const { error } = await supabase
          .from('users')
          .update({
            email_address: email,
            username: user.username || null,
            first_name: user.first_name || null,
            last_name: user.last_name || null,
            profile_image_url: user.image_url || null
          })
          .eq('id', user.id)
        if (error) {
          console.error('Update error:', error)
          return new Response('Database error', { status: 500 })
        }
        console.log('User updated:', user)
        break
      }

      case 'user.deleted': {
        const { error } = await supabase.from('users').delete().eq('id', user.id)
        if (error) {
          console.error('Delete error:', error)
          return new Response('Database error', { status: 500 })
        }
        console.log('User deleted:', user)
        break
      }

      default: {
        console.log(`Unhandled event type: ${eventType}`)
        break
      }
    }

    return new Response('Webhook processed', { status: 200 })
  } catch (err) {
    console.error('Webhook handler error:', err)
    return new Response(
      `Webhook error: ${err instanceof Error ? err.message : 'Unknown error'}`,
      { status: 400 }
    )
  }
}