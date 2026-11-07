import { useSelection } from "../lib/selection";
import { CveDetailView } from "./CveDetail";
import { Drawer } from "./Drawer";
import { StoryDetail } from "./StoryDetail";

/** Mounted once in the shell: shows the drawer for `?cve=` or `?story=`, nothing otherwise (`?country=` is the dashboard side panel). */
export function DrawerHost() {
  const { selection, clear } = useSelection();
  if (!selection) return null;
  if (selection.kind === "cve") {
    return (
      <Drawer heading={<span className="mono">{selection.id}</span>} onClose={clear} focusKey={`cve:${selection.id}`}>
        <CveDetailView id={selection.id} />
      </Drawer>
    );
  }
  if (selection.kind === "country") return null; // the dashboard side panel shows countries
  return (
    <Drawer heading="Story" onClose={clear} focusKey={`story:${selection.url ?? ""}`}>
      <StoryDetail url={selection.url} />
    </Drawer>
  );
}
