import en from './en.json';
import vi from './vi.json';

const translations: Record<string, Record<string, string>> = { en, vi };

export type LangKey = keyof typeof en;

export function t(key: string, lang: string = 'en'): string {
  return translations[lang]?.[key] ?? translations['en'][key] ?? key;
}

export function getLanguages(): { code: string; label: string }[] {
  return [
    { code: 'en', label: 'English' },
    { code: 'vi', label: 'Tiếng Việt' },
  ];
}
