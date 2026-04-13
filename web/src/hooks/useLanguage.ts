import { useState, useCallback } from 'react';
import { t as translate } from '../i18n';

export function useLanguage(initial: string = 'en') {
  const [lang, setLang] = useState(() => {
    return localStorage.getItem('pqc-lang') || initial;
  });

  const switchLang = useCallback((code: string) => {
    setLang(code);
    localStorage.setItem('pqc-lang', code);
  }, []);

  const t = useCallback((key: string) => translate(key, lang), [lang]);

  return { lang, switchLang, t };
}
