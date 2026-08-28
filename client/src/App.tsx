import { Toaster } from "sonner";
import Home from "./pages/Home";

export default function App() {
  return (
    <>
      <Toaster position="top-center" richColors theme="system" />
      <Home />
    </>
  );
}


