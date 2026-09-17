import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { CheckCircle2, Loader2 } from "lucide-react";
import { supabase } from "../lib/supabase";

const ZohoBooksCallbackPage = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [message, setMessage] = useState("Completing your secure Zoho Books connection…");

  useEffect(() => {
    let active = true;
    const complete = async () => {
      const code = searchParams.get("code");
      const state = searchParams.get("state");
      const providerError = searchParams.get("error");
      if (providerError || !code || !state) {
        navigate("/books?error=authorization", { replace: true });
        return;
      }

      const { data } = await supabase.auth.getSession();
      if (!data.session) {
        navigate("/login?returnTo=%2Fbooks", { replace: true });
        return;
      }

      const response = await fetch("/api/zoho/books/callback", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${data.session.access_token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ code, state }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || "Zoho authorization failed");
      if (active) {
        setMessage("Zoho Books connected. Redirecting…");
        setTimeout(() => navigate("/books", { replace: true }), 500);
      }
    };

    complete().catch(() => navigate("/books?error=authorization", { replace: true }));
    return () => { active = false; };
  }, [navigate, searchParams]);

  return <div className="min-h-[60vh] flex items-center justify-center px-4"><div className="text-center"><div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-sheraton-gold/15">{message.startsWith("Zoho Books connected") ? <CheckCircle2 className="h-7 w-7 text-green-600" /> : <Loader2 className="h-7 w-7 animate-spin text-sheraton-gold" />}</div><h1 className="text-xl font-semibold text-sheraton-navy">{message}</h1></div></div>;
};

export default ZohoBooksCallbackPage;
