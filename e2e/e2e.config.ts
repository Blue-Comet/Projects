import type { E2EConfig } from 'e2e';
import { web } from '@e2e-dev/web';
import { createOpenAICompatible } from '@ai-sdk/openai-compatible';

export default {
  agents: {
    default: {
      model: createOpenAICompatible({
        name: 'gemini',
        baseURL: 'https://generativelanguage.googleapis.com/v1beta/openai/',
        apiKey: process.env.OPENAI_API_KEY,
      }).chatModel('gemini-3.8-flash'),
      system: 'You are a thorough QA agent. Verify every outcome.',
    },
  },
  targets: [{
    engine: web(),
    app: {
      url: process.env.APP_URL ?? 'https://stg.sharetreats.ph/welcome',
    },
  }],
} satisfies E2EConfig;
