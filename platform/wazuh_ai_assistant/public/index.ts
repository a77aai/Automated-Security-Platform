import { PluginInitializerContext } from '../../../src/core/public';
import { WazuhAiAssistantPlugin } from './plugin';

console.log('[wazuhAiAssistant] public bundle loaded');

export function plugin(initializerContext: PluginInitializerContext) {
  console.log('[wazuhAiAssistant] plugin initializer called');
  return new WazuhAiAssistantPlugin(initializerContext);
}