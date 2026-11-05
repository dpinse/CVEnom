import { useSelection } from "../lib/selection";
import { CveDetailView } from "./CveDetail";
import { Drawer } from "./Drawer";
import { StoryDetail } from "./StoryDetail";

/** Mounted once in the shell: shows the drawer for `?cve=` or `?story=`, nothing otherwise. */
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
  return (
    <Drawer heading="Story" onClose={clear} focusKey={`story:${selection.url}`}>
      <StoryDetail url={selection.url} />
    </Drawer>
  );
}
