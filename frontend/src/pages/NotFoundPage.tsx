import { Link } from "react-router-dom";
import { ErrorState } from "../components/ui";
import { usePageTitle } from "../hooks/usePageTitle";

export function NotFoundPage() {
  usePageTitle("Not found");
  return (
    <div className="space-y-3">
      <ErrorState title="Page not found" message="This route is not part of the False Alarm console." />
      <Link to="/" className="inline-block text-[12px] text-accent hover:underline">
        Back to alert queue
      </Link>
    </div>
  );
}
