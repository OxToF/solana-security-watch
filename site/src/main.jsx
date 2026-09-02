import React, { useMemo } from "react";
import { createRoot } from "react-dom/client";
import { ConnectionProvider, WalletProvider } from "@solana/wallet-adapter-react";
import { WalletModalProvider } from "@solana/wallet-adapter-react-ui";
import { PhantomWalletAdapter, SolflareWalletAdapter } from "@solana/wallet-adapter-wallets";
import "@solana/wallet-adapter-react-ui/styles.css";
import "./styles.css";
import App from "./App.jsx";

// Browser-usable RPC. The public mainnet-beta endpoint rejects browser requests
// (403), so this MUST be a real RPC (Helius/QuickNode) set as VITE_SOLANA_RPC.
const RPC = import.meta.env.VITE_SOLANA_RPC || "https://api.mainnet-beta.solana.com";

function Root() {
  // Phantom + Solflare are registered explicitly; other Wallet-Standard wallets
  // (Backpack, etc.) are auto-detected by the adapter.
  const wallets = useMemo(() => [new PhantomWalletAdapter(), new SolflareWalletAdapter()], []);
  return (
    <ConnectionProvider endpoint={RPC}>
      <WalletProvider wallets={wallets} autoConnect={false}>
        <WalletModalProvider>
          <App />
        </WalletModalProvider>
      </WalletProvider>
    </ConnectionProvider>
  );
}

createRoot(document.getElementById("root")).render(<Root />);

// build: pick up VITE_SOLANA_RPC env
