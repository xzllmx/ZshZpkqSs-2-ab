-- Zoho tokens are server-only. The browser must never query this table directly.

ALTER TABLE public.zoho_books_integrations ENABLE ROW LEVEL SECURITY;

CREATE UNIQUE INDEX IF NOT EXISTS zoho_books_integrations_user_id_key
  ON public.zoho_books_integrations (user_id);

DROP POLICY IF EXISTS "Users can read own Zoho integration"
  ON public.zoho_books_integrations;
DROP POLICY IF EXISTS "Users can insert own Zoho integration"
  ON public.zoho_books_integrations;
DROP POLICY IF EXISTS "Users can update own Zoho integration"
  ON public.zoho_books_integrations;

-- Intentionally no client policies are created. The service-role backend
-- handles status, token exchange, refresh, and disconnect operations.

REVOKE ALL ON TABLE public.zoho_books_integrations FROM anon, authenticated;
GRANT ALL ON TABLE public.zoho_books_integrations TO service_role;
