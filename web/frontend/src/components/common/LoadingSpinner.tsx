export function LoadingSpinner({ text = 'Loading...' }: { text?: string }) {
  return (
    <div className="flex flex-col items-center gap-2 p-8">
      <span className="loading loading-spinner loading-lg text-primary"></span>
      <p className="text-sm text-base-content/70">{text}</p>
    </div>
  );
}
