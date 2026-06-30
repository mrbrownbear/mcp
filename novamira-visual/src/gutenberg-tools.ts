import { exposeTools } from "./expose-tools";
import { makeUseSkillTool } from "./tools/use-skill";
import { listBlockTypesTool } from "./tools/gutenberg/list-block-types";
import { getBlockSchemaTool } from "./tools/gutenberg/get-block-schema";
import { getPageStructureTool } from "./tools/gutenberg/get-page-structure";
import { getBlockAttributesTool } from "./tools/gutenberg/get-block-attributes";
import { getEditorSettingsTool } from "./tools/gutenberg/get-editor-settings";
import { createBlockTool } from "./tools/gutenberg/create-block";
import { updateBlockTool } from "./tools/gutenberg/update-block";
import { deleteBlockTool } from "./tools/gutenberg/delete-block";
import { moveBlockTool } from "./tools/gutenberg/move-block";
import { replaceInnerBlocksTool } from "./tools/gutenberg/replace-inner-blocks";
import { undoTool, redoTool, saveTool } from "./tools/gutenberg/history";

export const gutenbergTools = [
	listBlockTypesTool,
	getBlockSchemaTool,
	getPageStructureTool,
	getBlockAttributesTool,
	getEditorSettingsTool,
	createBlockTool,
	updateBlockTool,
	deleteBlockTool,
	moveBlockTool,
	replaceInnerBlocksTool,
	undoTool,
	redoTool,
	saveTool,
	makeUseSkillTool("gutenberg"),
];

export function exposeGutenbergTools(): void {
	exposeTools(gutenbergTools);
}
