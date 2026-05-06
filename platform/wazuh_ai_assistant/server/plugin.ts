import { Plugin, CoreSetup, CoreStart, PluginInitializerContext } from '../../../src/core/server';
import { defineRoutes } from './routes';

export class WazuhAiAssistantServerPlugin implements Plugin<void, void> {
  constructor(private readonly initializerContext: PluginInitializerContext) {}

  public setup(core: CoreSetup) {
    const router = core.http.createRouter();
    defineRoutes(router);
  }

  public start(core: CoreStart) {}

  public stop() {}
}