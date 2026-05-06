import { PluginInitializerContext } from '../../../src/core/server';
import { WazuhAiAssistantServerPlugin } from './plugin';

export function plugin(initializerContext: PluginInitializerContext) {
  return new WazuhAiAssistantServerPlugin(initializerContext);
}
