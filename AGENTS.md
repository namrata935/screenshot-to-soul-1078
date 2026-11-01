<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

- Secure VMS is frontend-only: all data comes from `src/lib/mock-data.ts` (labelled DEMO DATA); no backend calls. Why: prototype scope.
- Shared VMS UI lives in `src/components/vms/`; the app shell wraps every route in `__root.tsx`. Why: one consistent SOC layout.
