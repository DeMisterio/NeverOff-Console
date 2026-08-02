/**
 * Structured reason catalogue.
 *
 * §3.3 requires every enforcement action to carry a reason *category*, and §4
 * requires the ban screen to render "the specific reason the admin selected …
 * in the user's language, with a link to the specific policy clause violated".
 * Free text cannot do that — it cannot be translated, cannot be linked to a
 * policy clause, and cannot be aggregated for the transparency report. So the
 * reason is a code from this catalogue, and the free-text note sits alongside it
 * for the appeal reviewer rather than being shown to the user.
 *
 * The two-level taxonomy mirrors §6.2 so that report categories and enforcement
 * reasons aggregate against each other without a translation table.
 */

export const REASON_CATEGORIES = [
  'spam_scams',
  'harassment',
  'hate_speech',
  'violence',
  'adult_sexual',
  'child_safety',
  'self_harm',
  'illegal_goods',
  'impersonation',
  'misinformation',
  'intellectual_property',
  'other',
] as const;

export type ReasonCategory = (typeof REASON_CATEGORIES)[number];

export interface ReasonCategoryMeta {
  readonly code: ReasonCategory;
  readonly policySection: string;
  /**
   * Routed out of the ordinary queue entirely (§6.7). Never appears in the
   * general moderation UI and never reaches third-party analytics.
   */
  readonly isolatedPipeline: boolean;
  /** Routed to the safety escalation path rather than the ordinary queue (§6.2). */
  readonly safetyEscalation: boolean;
  /** Baseline triage weight; the queue scorer multiplies this by volume etc. */
  readonly severityWeight: number;
}

export const CATEGORY_META: Readonly<Record<ReasonCategory, ReasonCategoryMeta>> = {
  spam_scams: { code: 'spam_scams', policySection: '3', isolatedPipeline: false, safetyEscalation: false, severityWeight: 2 },
  harassment: { code: 'harassment', policySection: '4', isolatedPipeline: false, safetyEscalation: false, severityWeight: 4 },
  hate_speech: { code: 'hate_speech', policySection: '5', isolatedPipeline: false, safetyEscalation: false, severityWeight: 5 },
  violence: { code: 'violence', policySection: '6', isolatedPipeline: false, safetyEscalation: false, severityWeight: 6 },
  adult_sexual: { code: 'adult_sexual', policySection: '7', isolatedPipeline: false, safetyEscalation: false, severityWeight: 5 },
  child_safety: { code: 'child_safety', policySection: '8', isolatedPipeline: true, safetyEscalation: true, severityWeight: 10 },
  self_harm: { code: 'self_harm', policySection: '9', isolatedPipeline: false, safetyEscalation: true, severityWeight: 9 },
  illegal_goods: { code: 'illegal_goods', policySection: '10', isolatedPipeline: false, safetyEscalation: false, severityWeight: 4 },
  impersonation: { code: 'impersonation', policySection: '11', isolatedPipeline: false, safetyEscalation: false, severityWeight: 3 },
  misinformation: { code: 'misinformation', policySection: '12', isolatedPipeline: false, safetyEscalation: false, severityWeight: 2 },
  intellectual_property: { code: 'intellectual_property', policySection: '13', isolatedPipeline: false, safetyEscalation: false, severityWeight: 2 },
  other: { code: 'other', policySection: '1', isolatedPipeline: false, safetyEscalation: false, severityWeight: 1 },
};

export interface ReasonMeta {
  readonly code: string;
  readonly category: ReasonCategory;
  /** Clause within the published policy, e.g. "4.2". Rendered as a deep link. */
  readonly policyClause: string;
  /** Whether an enforcement citing this reason can be appealed by the user. */
  readonly appealable: boolean;
  /**
   * Reasons that must never be selectable in the general moderation UI because
   * their category runs through the isolated pipeline.
   */
  readonly isolated: boolean;
}

function reason(
  code: string,
  category: ReasonCategory,
  clause: string,
  opts: { appealable?: boolean } = {},
): ReasonMeta {
  return {
    code,
    category,
    policyClause: clause,
    appealable: opts.appealable ?? true,
    isolated: CATEGORY_META[category].isolatedPipeline,
  };
}

export const REASONS: readonly ReasonMeta[] = [
  // Spam & scams
  reason('spam.unsolicited_bulk', 'spam_scams', '3.1'),
  reason('spam.phishing', 'spam_scams', '3.2'),
  reason('spam.fake_giveaway', 'spam_scams', '3.3'),
  reason('spam.investment_fraud', 'spam_scams', '3.4'),
  reason('spam.platform_impersonation', 'spam_scams', '3.5'),

  // Harassment & bullying
  reason('harassment.targeted_abuse', 'harassment', '4.1'),
  reason('harassment.threats', 'harassment', '4.2'),
  reason('harassment.stalking', 'harassment', '4.3'),
  reason('harassment.coordinated_pile_on', 'harassment', '4.4'),
  reason('harassment.doxxing', 'harassment', '4.5'),

  // Hate speech
  reason('hate.protected_characteristic', 'hate_speech', '5.1'),
  reason('hate.dehumanising_content', 'hate_speech', '5.2'),

  // Violence
  reason('violence.threat', 'violence', '6.1'),
  reason('violence.incitement', 'violence', '6.2'),
  reason('violence.glorification', 'violence', '6.3'),
  reason('violence.violent_extremism', 'violence', '6.4', { appealable: false }),

  // Adult & sexual content
  reason('adult.ncii', 'adult_sexual', '7.1', { appealable: false }),
  reason('adult.unsolicited_sexual', 'adult_sexual', '7.2'),
  reason('adult.sexual_services', 'adult_sexual', '7.3'),

  // Child safety — isolated pipeline (§6.7). Present so the taxonomy is
  // complete and reports can be *routed*, never selectable in general tooling.
  reason('child_safety.csam', 'child_safety', '8.1', { appealable: false }),
  reason('child_safety.grooming', 'child_safety', '8.2', { appealable: false }),
  reason('child_safety.endangerment', 'child_safety', '8.3', { appealable: false }),

  // Self-harm & suicide — routed to the safety escalation path, never actioned
  // as an ordinary violation. Present for routing, not for punishment.
  reason('self_harm.risk_disclosure', 'self_harm', '9.1'),
  reason('self_harm.promotion', 'self_harm', '9.2'),

  // Illegal goods
  reason('illegal.drugs', 'illegal_goods', '10.1'),
  reason('illegal.weapons', 'illegal_goods', '10.2'),
  reason('illegal.stolen_data', 'illegal_goods', '10.3'),
  reason('illegal.counterfeit', 'illegal_goods', '10.4'),

  // Impersonation
  reason('impersonation.person', 'impersonation', '11.1'),
  reason('impersonation.brand', 'impersonation', '11.2'),
  reason('impersonation.official_account', 'impersonation', '11.3'),

  // Misinformation
  reason('misinformation.civic', 'misinformation', '12.1'),
  reason('misinformation.health', 'misinformation', '12.2'),

  // Intellectual property
  reason('ip.copyright', 'intellectual_property', '13.1'),
  reason('ip.trademark', 'intellectual_property', '13.2'),

  // Other
  reason('other.terms_violation', 'other', '1.1'),
  reason('other.ban_evasion', 'other', '1.2'),
  reason('other.security_abuse', 'other', '1.3'),
];

const REASON_BY_CODE = new Map(REASONS.map((r) => [r.code, r]));

export function reasonMeta(code: string): ReasonMeta | undefined {
  return REASON_BY_CODE.get(code);
}

export function isReasonCode(value: unknown): value is string {
  return typeof value === 'string' && REASON_BY_CODE.has(value);
}

/** Reasons a general-queue moderator may pick. Excludes the isolated pipeline. */
export const SELECTABLE_REASONS: readonly ReasonMeta[] = REASONS.filter((r) => !r.isolated);

// ---------------------------------------------------------------------------
// Localisation
// ---------------------------------------------------------------------------

/**
 * Every user-facing string here is rendered on the ban screen and in the appeal
 * form, so it must exist in the user's language (§9.3 i18n, §4).
 *
 * Locales are plain records rather than a library so the same bundle can be
 * served to the Android client verbatim over the status endpoint — the app then
 * needs no reason-code table of its own and never falls out of sync.
 *
 * Adding a locale means adding a key here; `localiseReason` falls back to `en`
 * for any code a locale has not translated yet, so a partial locale degrades to
 * English rather than to a raw code.
 */
export type LocaleCode = 'en' | 'ru';

export const DEFAULT_LOCALE: LocaleCode = 'en';

type ReasonStrings = Record<string, string>;

const EN: ReasonStrings = {
  'category.spam_scams': 'Spam and scams',
  'category.harassment': 'Harassment and bullying',
  'category.hate_speech': 'Hate speech',
  'category.violence': 'Violence',
  'category.adult_sexual': 'Adult and sexual content',
  'category.child_safety': 'Child safety',
  'category.self_harm': 'Self-harm and suicide',
  'category.illegal_goods': 'Illegal goods',
  'category.impersonation': 'Impersonation',
  'category.misinformation': 'Misinformation',
  'category.intellectual_property': 'Intellectual property',
  'category.other': 'Other',

  'spam.unsolicited_bulk': 'Sending unsolicited bulk messages',
  'spam.phishing': 'Phishing or credential theft',
  'spam.fake_giveaway': 'Fake giveaway or prize scam',
  'spam.investment_fraud': 'Investment or cryptocurrency fraud',
  'spam.platform_impersonation': 'Impersonating NeverOff or its staff',
  'harassment.targeted_abuse': 'Targeted abuse of another person',
  'harassment.threats': 'Threatening another person',
  'harassment.stalking': 'Stalking or persistent unwanted contact',
  'harassment.coordinated_pile_on': 'Taking part in a coordinated pile-on',
  'harassment.doxxing': 'Publishing someone’s private information',
  'hate.protected_characteristic': 'Attacking people over a protected characteristic',
  'hate.dehumanising_content': 'Sharing dehumanising content',
  'violence.threat': 'Threatening violence',
  'violence.incitement': 'Inciting violence',
  'violence.glorification': 'Glorifying violence',
  'violence.violent_extremism': 'Sharing violent extremist content',
  'adult.ncii': 'Sharing intimate images without consent',
  'adult.unsolicited_sexual': 'Sending unsolicited sexual content',
  'adult.sexual_services': 'Advertising sexual services',
  'child_safety.csam': 'Child sexual abuse material',
  'child_safety.grooming': 'Grooming behaviour towards a minor',
  'child_safety.endangerment': 'Endangering a minor',
  'self_harm.risk_disclosure': 'Content indicating risk of self-harm',
  'self_harm.promotion': 'Promoting or encouraging self-harm',
  'illegal.drugs': 'Selling controlled substances',
  'illegal.weapons': 'Selling weapons',
  'illegal.stolen_data': 'Trading stolen data or credentials',
  'illegal.counterfeit': 'Selling counterfeit goods',
  'impersonation.person': 'Impersonating another person',
  'impersonation.brand': 'Impersonating a brand',
  'impersonation.official_account': 'Impersonating an official account',
  'misinformation.civic': 'Sharing misleading civic information',
  'misinformation.health': 'Sharing misleading health information',
  'ip.copyright': 'Copyright infringement',
  'ip.trademark': 'Trademark infringement',
  'other.terms_violation': 'Breaking the Terms of Service',
  'other.ban_evasion': 'Evading a previous suspension',
  'other.security_abuse': 'Abusing or attacking platform infrastructure',
};

const RU: ReasonStrings = {
  'category.spam_scams': 'Спам и мошенничество',
  'category.harassment': 'Травля и преследование',
  'category.hate_speech': 'Язык вражды',
  'category.violence': 'Насилие',
  'category.adult_sexual': 'Контент для взрослых',
  'category.child_safety': 'Безопасность детей',
  'category.self_harm': 'Самоповреждение',
  'category.illegal_goods': 'Запрещённые товары',
  'category.impersonation': 'Выдача себя за другого',
  'category.misinformation': 'Дезинформация',
  'category.intellectual_property': 'Интеллектуальная собственность',
  'category.other': 'Другое',

  'spam.unsolicited_bulk': 'Массовая рассылка без согласия получателей',
  'spam.phishing': 'Фишинг или кража учётных данных',
  'spam.fake_giveaway': 'Ложный розыгрыш или призовая схема',
  'spam.investment_fraud': 'Инвестиционное или криптомошенничество',
  'spam.platform_impersonation': 'Выдача себя за NeverOff или его сотрудников',
  'harassment.targeted_abuse': 'Целенаправленная травля другого человека',
  'harassment.threats': 'Угрозы в адрес другого человека',
  'harassment.stalking': 'Преследование или навязчивые контакты',
  'harassment.coordinated_pile_on': 'Участие в скоординированной травле',
  'harassment.doxxing': 'Публикация чужих личных данных',
  'hate.protected_characteristic': 'Нападки по защищённому признаку',
  'hate.dehumanising_content': 'Распространение дегуманизирующего контента',
  'violence.threat': 'Угроза насилием',
  'violence.incitement': 'Подстрекательство к насилию',
  'violence.glorification': 'Прославление насилия',
  'violence.violent_extremism': 'Экстремистский контент',
  'adult.ncii': 'Распространение интимных изображений без согласия',
  'adult.unsolicited_sexual': 'Отправка нежелательного сексуального контента',
  'adult.sexual_services': 'Реклама сексуальных услуг',
  'child_safety.csam': 'Материалы с сексуальным насилием над детьми',
  'child_safety.grooming': 'Груминг в отношении несовершеннолетнего',
  'child_safety.endangerment': 'Создание угрозы для несовершеннолетнего',
  'self_harm.risk_disclosure': 'Контент, указывающий на риск самоповреждения',
  'self_harm.promotion': 'Пропаганда самоповреждения',
  'illegal.drugs': 'Продажа запрещённых веществ',
  'illegal.weapons': 'Продажа оружия',
  'illegal.stolen_data': 'Торговля крадеными данными',
  'illegal.counterfeit': 'Продажа контрафакта',
  'impersonation.person': 'Выдача себя за другого человека',
  'impersonation.brand': 'Выдача себя за бренд',
  'impersonation.official_account': 'Выдача себя за официальный аккаунт',
  'misinformation.civic': 'Распространение ложной общественной информации',
  'misinformation.health': 'Распространение ложной медицинской информации',
  'ip.copyright': 'Нарушение авторских прав',
  'ip.trademark': 'Нарушение прав на товарный знак',
  'other.terms_violation': 'Нарушение условий использования',
  'other.ban_evasion': 'Обход ранее вынесенной блокировки',
  'other.security_abuse': 'Атаки на инфраструктуру платформы',
};

const LOCALES: Readonly<Record<LocaleCode, ReasonStrings>> = { en: EN, ru: RU };

export function isLocaleCode(value: unknown): value is LocaleCode {
  return value === 'en' || value === 'ru';
}

/** Resolve a display string, falling back to English then to the raw code. */
export function localise(key: string, locale: LocaleCode = DEFAULT_LOCALE): string {
  return LOCALES[locale]?.[key] ?? EN[key] ?? key;
}

export function localiseReason(code: string, locale: LocaleCode = DEFAULT_LOCALE): string {
  return localise(code, locale);
}

export function localiseCategory(category: ReasonCategory, locale: LocaleCode = DEFAULT_LOCALE): string {
  return localise(`category.${category}`, locale);
}

/**
 * Everything the ban screen needs for one reason, in one payload, so the
 * Android client renders from the server's catalogue rather than its own copy.
 */
export interface LocalisedReason {
  readonly code: string;
  readonly category: ReasonCategory;
  readonly categoryLabel: string;
  readonly label: string;
  readonly policyClause: string;
  readonly policyUrl: string;
  readonly appealable: boolean;
}

export function describeReason(
  code: string,
  locale: LocaleCode = DEFAULT_LOCALE,
  policyBaseUrl = 'https://neveroff.app/policy',
): LocalisedReason | null {
  const meta = REASON_BY_CODE.get(code);
  if (!meta) return null;
  return {
    code: meta.code,
    category: meta.category,
    categoryLabel: localiseCategory(meta.category, locale),
    label: localiseReason(meta.code, locale),
    policyClause: meta.policyClause,
    policyUrl: `${policyBaseUrl}#${meta.policyClause}`,
    appealable: meta.appealable,
  };
}
