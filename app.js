/**
 * ============================================================================
 * ESCUDO DIGITAL — Motor de Detecção de Golpes, Vírus & Engenharia Social + IA
 * Compatível com GitHub Pages (Client-Side) e Cloudflare Pages / Workers AI
 * ============================================================================
 */

(function () {
  'use strict';

  // --- Estado da Aplicação ---
  const state = {
    category: 'auto',
    channel: 'Qualquer canal',
    aiConfig: {
      mode: localStorage.getItem('ed_ai_mode') || 'auto',
      cfEndpoint:
        localStorage.getItem('ed_cf_endpoint') ||
        (window.location.hostname.endsWith('github.io')
          ? 'https://escudo-digital.fan-gram-5bc.workers.dev/api/analyze'
          : '/api/analyze'),
      geminiKey: localStorage.getItem('ed_gemini_key') || ''
    },
    lastResult: null,
    history: JSON.parse(localStorage.getItem('ed_history') || '[]')
  };

  // --- Base de Conhecimento: Domínios Oficiais Confiáveis ---
  const OFFICIAL_BRANDS = [
    { name: 'Nubank', keywords: ['nubank', 'nuconta'], domains: ['nubank.com.br'] },
    { name: 'Itaú', keywords: ['itau', 'itaú'], domains: ['itau.com.br'] },
    { name: 'Bradesco', keywords: ['bradesco'], domains: ['bradesco.com.br', 'banco.bradesco'] },
    { name: 'Banco do Brasil', keywords: ['bancodobrasil', 'bb'], domains: ['bb.com.br'] },
    { name: 'Caixa Econômica', keywords: ['caixa', 'caixatem'], domains: ['caixa.gov.br'] },
    { name: 'Santander', keywords: ['santander'], domains: ['santander.com.br'] },
    { name: 'Banco Inter', keywords: ['bancointer'], domains: ['inter.co', 'bancointer.com.br'] },
    { name: 'Gov.br / Governo Federal', keywords: ['govbr', 'receitafederal', 'meuinss', 'desenrola', 'serasa'], domains: ['gov.br', 'serasa.com.br'] },
    { name: 'Correios', keywords: ['correios', 'sedex', 'pac'], domains: ['correios.com.br'] },
    { name: 'Mercado Livre / Mercado Pago', keywords: ['mercadolivre', 'mercadopago'], domains: ['mercadolivre.com.br', 'mercadopago.com.br'] },
    { name: 'Shopee', keywords: ['shopee'], domains: ['shopee.com.br'] },
    { name: 'Amazon', keywords: ['amazon'], domains: ['amazon.com.br', 'amazon.com'] },
    { name: 'Magazine Luiza', keywords: ['magalu', 'magazineluiza'], domains: ['magazineluiza.com.br', 'magalu.com'] },
    { name: 'Instagram', keywords: ['instagram'], domains: ['instagram.com'] },
    { name: 'WhatsApp', keywords: ['whatsapp'], domains: ['whatsapp.com', 'wa.me'] },
    { name: 'Google', keywords: ['google'], domains: ['google.com', 'google.com.br'] }
  ];

  const SUSPICIOUS_TLDS = [
    '.xyz', '.top', '.click', '.site', '.online', '.shop', '.vip', '.loan',
    '.win', '.icu', '.buzz', '.club', '.work', '.tk', '.ml', '.ga', '.cf',
    '.gq', '.monster', '.rest', '.fit', '.live', '.life', '.promo', '.sbs'
  ];

  const URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'cutt.ly', 'is.gd', 't.co', 'shorturl.at',
    'rb.gy', 'encurtador.com.br', 'abre.ai', 'bityli.com', 'tiny.cc', 'rebrand.ly'
  ];

  const DANGEROUS_EXTENSIONS = [
    { ext: '.apk', label: 'Aplicativo Android fora da loja oficial (.APK)', risk: 55 },
    { ext: '.exe', label: 'Programa executável de Windows (.EXE)', risk: 55 },
    { ext: '.scr', label: 'Protetor de tela executável (.SCR - muito usado em vírus bancários)', risk: 60 },
    { ext: '.bat', label: 'Script de comandos (.BAT)', risk: 55 },
    { ext: '.vbs', label: 'Script Visual Basic (.VBS)', risk: 55 },
    { ext: '.msi', label: 'Instalador de sistema (.MSI)', risk: 50 },
    { ext: '.cmd', label: 'Script de sistema (.CMD)', risk: 50 },
    { ext: '.zip', label: 'Arquivo compactado (.ZIP) — frequentemente esconde trojans', risk: 30 },
    { ext: '.rar', label: 'Arquivo compactado (.RAR) — pode ocultar malware', risk: 30 }
  ];

  // --- Padrões de Engenharia Social e Golpes em Conversas / Perfis / PIX ---
  const SCAM_PATTERNS = [
    {
      id: 'fake_relative',
      category: 'Golpe do Novo Número / Falso Parente',
      weight: 45,
      regex: /(troquei de n[uú]mero|n[uú]mero novo|celular (quebrou|caiu|foi para a assist[eê]ncia|molhou)|oi (m[aã]e|pai|tia|v[oó])[\s,!.]*agenda esse|pagar um boleto urgente|meu app do banco bloqueou)/i,
      title: 'Padrão clássico do "Golpe do Novo Número"',
      detail: 'Golpistas fingem ser filhos ou parentes com celular quebrado para pedir transferências PIX ou pagamento de boletos urgentes.'
    },
    {
      id: 'fake_bank_center',
      category: 'Falsa Central de Segurança Bancária',
      weight: 48,
      regex: /(compra (suspeita|aprovada|em an[aá]lise) no valor|reconhece (essa|esta) (compra|transa[cç][aã]o)|central de seguran[cç]a|m[oó]dulo de seguran[cç]a|fazer um pix de (estorno|devolu[cç][aã]o|valida[cç][aã]o|teste)|cancelar a compra digite|ligue urgente para 0800)/i,
      title: 'Tentativa de Falsa Central de Banco / Suporte',
      detail: 'Criminosos criam pânico sobre uma falsa compra no cartão para induzir você a clicar em links, instalar apps espiões ou transferir dinheiro.'
    },
    {
      id: 'remote_access',
      category: 'Roubo de Controle do Aparelho (RAT)',
      weight: 55,
      regex: /(anydesk|teamviewer|rustdesk|quicksupport|acesso remoto|varredura de seguran[cç]a no aparelho|compartilhar a tela)/i,
      title: 'Pedido de Acesso Remoto ou Varredura Falsa',
      detail: 'Nenhum banco pede para instalar programas de suporte remoto ou compartilhar tela. Isso dá controle total do seu celular ao golpista.'
    },
    {
      id: 'customs_correios',
      category: 'Golpe da Falsa Taxa de Alfândega / Correios',
      weight: 45,
      regex: /(objeto (retido|aguardando pagamento|barrado)|taxa (alfandeg[aá]ria|de libera[cç][aã]o|de despacho)|regularize (sua encomenda|seu envio)|alf[aâ]ndega|tributa[cç][aã]o postal)/i,
      title: 'Falsa Cobrança de Encomenda Retida',
      detail: 'Mensagens de SMS ou WhatsApp cobrando taxas de entrega com link próprio quase sempre levam a páginas falsas que roubam PIX e dados do cartão.'
    },
    {
      id: 'two_factor_theft',
      category: 'Clonagem de WhatsApp / Roubo de Conta',
      weight: 52,
      regex: /(c[oó]digo de (6 d[ií]gitos|verifica[cç][aã]o|confirma[cç][aã]o|seguran[cç]a)|me passa o c[oó]digo que chegou por sms|confirmar seu an[uú]ncio na olx|confirmar reserva com o c[oó]digo)/i,
      title: 'Tentativa de Roubo de Código de 6 Dígitos (2FA)',
      detail: 'Quem pede um código recebido por SMS está tentando clonar seu WhatsApp, Instagram ou redefinir sua senha bancária.'
    },
    {
      id: 'task_scam_pix_multiplier',
      category: 'Golpe da Tarefa Remunerada / Robô do PIX',
      weight: 46,
      regex: /(curtir v[ií]deos e ganhar|ganhe de r\$\s*\d+ a r\$\s*\d+ por dia|tarefas? (remuneradas?|pr[eé]-pagas?)|avaliar produtos na (shopee|amazon|shein)|urubu do pix|rob[oô] do pix|multiplicar seu pix|retorno garantido em minutos|desbloquear n[ií]vel vip)/i,
      title: 'Promessa Irreal de Dinheiro Fácil ou Multiplicação de PIX',
      detail: 'Esquemas de "curtir vídeos" ou "multiplicar PIX" pagam centavos no início e depois exigem depósitos altos que nunca são devolvidos.'
    },
    {
      id: 'fake_store_social',
      category: 'Loja Suspeita / Fraude de E-commerce',
      weight: 38,
      regex: /(iphone (de vitrine|lacrado) por r\$\s*[12]\.?\d{2}|pagamento somente via pix|desconto especial s[oó] no pix agora|queima de estoque urgente|receita federal leil[aã]o de lotes)/i,
      title: 'Oferta Comercial com Forte Indício de Loja Fantasma',
      detail: 'Aparelhos caros por preços muito abaixo do mercado e exigência de pagamento antecipado apenas por PIX são marcas registradas de perfis falsos.'
    },
    {
      id: 'urgency_pressure',
      category: 'Gatilho Psicológico de Urgência / Ameaça',
      weight: 22,
      regex: /(bloqueio imediato do seu cpf|[uú]ltimo aviso antes do bloqueio|sua conta ser[aá] encerrada hoje|pague nos pr[oó]ximos \d+ minutos|intima[cç][aã]o judicial urgente|mandado de bloqueio)/i,
      title: 'Pressão Psicológica e Falsa Urgência',
      detail: 'O texto usa medo ou pressa extrema para impedir que você pare, pense e confira a informação em um canal oficial.'
    },
    {
      id: 'prize_gov_benefit',
      category: 'Falso Prêmio / Auxílio / Valores a Receber',
      weight: 38,
      regex: /(valores esquecidos liberados no seu cpf|resgate imediato via pix|voc[eê] foi sorteado|pague apenas a taxa de envio do brinde|indeniza[cç][aã]o liberada pelo governo)/i,
      title: 'Isca de Falso Benefício, Sorteio ou Valores a Receber',
      detail: 'O Banco Central e órgãos públicos não enviam links por WhatsApp/SMS para resgate de valores nem cobram taxas para liberar benefícios.'
    }
  ];

  // --- Exemplos Reais para Teste em 1 Clique ---
  const EXAMPLES = {
    correios: {
      category: 'chat',
      channel: 'SMS / Ligação',
      text: 'CORREIOS INFORMA: Seu pacote BR8941209BR foi retido na alfândega por falta de pagamento da taxa de liberação (R$ 47,90). Regularize hoje para evitar devolução em: http://correios-taxas-br.xyz/pagar-guia'
    },
    whatsapp_filho: {
      category: 'chat',
      channel: 'WhatsApp',
      text: 'Oi mãe, tudo bem? Meu celular caiu e quebrou a tela, estou usando esse número novo provisório. Agenda aí! Mãe, meu app do banco bloqueou por causa da troca de aparelho e preciso pagar um fornecedor urgente de R$ 1.250,00 agora via PIX, você consegue fazer pra mim e te devolvo às 18h?'
    },
    loja_instagram: {
      category: 'profile',
      channel: 'Instagram / TikTok',
      checks: { chkLowPrice: true, chkOnlyPix: true, chkClosedComments: true, chkRecentAccount: true, chkNoCnpj: true, chkPressuring: true },
      text: 'Perfil @importados_outlet_vip_br no Instagram. Bio: "Lote Receita Federal! iPhone 15 Pro Max 256GB Lacrado por apenas R$ 1.890 à vista no PIX! Envio imediato para todo Brasil. Últimas 2 unidades do estoque promocional, chame no link da bio!"'
    },
    banco_apk: {
      category: 'link',
      channel: 'SMS / Ligação',
      text: 'ALERTA NUBANK: Compra suspeita aprovada no valor de R$ 3.490,00. Caso não reconheça, baixe imediatamente o Módulo de Segurança e Varredura para cancelar: http://nubank-seguranca-app.top/ModuloSegurancaNubank.apk'
    },
    renda_extra: {
      category: 'pix',
      channel: 'WhatsApp',
      text: 'Parabéns! Seu número foi selecionado para trabalhar em casa curtindo vídeos do TikTok e avaliando produtos da Shopee. Ganhe de R$ 300 a R$ 850 por dia direto no seu PIX! Para liberar a tarefa VIP nº 3 e receber R$ 1.200 de comissão, deposite a taxa de ativação de R$ 150 na chave PIX aleatória.'
    },
    seguro: {
      category: 'link',
      channel: 'Site / Loja',
      text: 'https://www.gov.br/pt-br/servicos'
    }
  };

  // --- Referências de Elementos do DOM ---
  const els = {
    catTabs: document.querySelectorAll('.cat-tab'),
    channelChips: document.querySelectorAll('.channel-chip'),
    profileExtraFields: document.getElementById('profileExtraFields'),
    scamInput: document.getElementById('scamInput'),
    inputLabel: document.getElementById('inputLabel'),
    btnPaste: document.getElementById('btnPaste'),
    btnClear: document.getElementById('btnClear'),
    btnAnalyze: document.getElementById('btnAnalyze'),
    examplePills: document.querySelectorAll('.example-pill'),

    emptyState: document.getElementById('emptyState'),
    loadingState: document.getElementById('loadingState'),
    loadingStepText: document.getElementById('loadingStepText'),
    resultContent: document.getElementById('resultContent'),

    riskBanner: document.getElementById('riskBanner'),
    gaugeProgress: document.getElementById('gaugeProgress'),
    riskPercent: document.getElementById('riskPercent'),
    riskLevelBadge: document.getElementById('riskLevelBadge'),
    threatCategoryBadge: document.getElementById('threatCategoryBadge'),
    resultHeadline: document.getElementById('resultHeadline'),
    resultSubheadline: document.getElementById('resultSubheadline'),

    btnShareWhatsapp: document.getElementById('btnShareWhatsapp'),
    btnCopyReport: document.getElementById('btnCopyReport'),
    copyReportText: document.getElementById('copyReportText'),

    aiVerdictText: document.getElementById('aiVerdictText'),
    aiEngineBadge: document.getElementById('aiEngineBadge'),
    aiStatusLabel: document.getElementById('aiStatusLabel'),

    extractedEntitiesBox: document.getElementById('extractedEntitiesBox'),
    entitiesList: document.getElementById('entitiesList'),
    signalsList: document.getElementById('signalsList'),
    preventionTipsList: document.getElementById('preventionTipsList'),

    historyList: document.getElementById('historyList'),
    btnClearHistory: document.getElementById('btnClearHistory'),

    btnToggleTheme: document.getElementById('btnToggleTheme'),
    iconSun: document.getElementById('iconSun'),
    iconMoon: document.getElementById('iconMoon'),

    btnOpenAiModal: document.getElementById('btnOpenAiModal'),
    btnMobAiSettings: document.getElementById('btnMobAiSettings'),
    btnCloseAiModal: document.getElementById('btnCloseAiModal'),
    aiModal: document.getElementById('aiModal'),
    aiModeSelect: document.getElementById('aiModeSelect'),
    cfEndpointInput: document.getElementById('cfEndpointInput'),
    geminiApiKeyInput: document.getElementById('geminiApiKeyInput'),
    btnSaveAiConfig: document.getElementById('btnSaveAiConfig'),

    // Checkboxes de Perfil
    chkLowPrice: document.getElementById('chkLowPrice'),
    chkOnlyPix: document.getElementById('chkOnlyPix'),
    chkClosedComments: document.getElementById('chkClosedComments'),
    chkRecentAccount: document.getElementById('chkRecentAccount'),
    chkNoCnpj: document.getElementById('chkNoCnpj'),
    chkPressuring: document.getElementById('chkPressuring')
  };

  // --- Inicialização ---
  function init() {
    initTheme();
    initAiConfigUI();
    renderHistory();
    bindEvents();
  }

  function initTheme() {
    const savedTheme = localStorage.getItem('ed_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeIcons(savedTheme);
  }

  function updateThemeIcons(theme) {
    if (theme === 'dark') {
      els.iconSun.classList.remove('hidden');
      els.iconMoon.classList.add('hidden');
    } else {
      els.iconSun.classList.add('hidden');
      els.iconMoon.classList.remove('hidden');
    }
  }

  function initAiConfigUI() {
    els.aiModeSelect.value = state.aiConfig.mode;
    els.cfEndpointInput.value = state.aiConfig.cfEndpoint;
    els.geminiApiKeyInput.value = state.aiConfig.geminiKey;
    updateAiStatusBadge();
  }

  function updateAiStatusBadge() {
    const mode = state.aiConfig.mode;
    if (mode === 'gemini' && state.aiConfig.geminiKey) {
      els.aiStatusLabel.textContent = 'IA: Google Gemini';
    } else if (mode === 'cloudflare') {
      els.aiStatusLabel.textContent = 'IA: Cloudflare AI';
    } else if (mode === 'local') {
      els.aiStatusLabel.textContent = 'IA: Local Offline';
    } else {
      els.aiStatusLabel.textContent = state.aiConfig.geminiKey ? 'IA: Híbrida + Gemini' : 'IA: Híbrida Ativa';
    }
  }

  // --- Eventos de Interface ---
  function bindEvents() {
    // Alternar Tema
    els.btnToggleTheme.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') || 'dark';
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('ed_theme', next);
      updateThemeIcons(next);
    });

    // Abas de Categoria
    els.catTabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        els.catTabs.forEach((t) => {
          t.classList.remove('active');
          t.setAttribute('aria-selected', 'false');
        });
        tab.classList.add('active');
        tab.setAttribute('aria-selected', 'true');
        state.category = tab.dataset.category;
        updateCategoryPrompts(state.category);
      });
    });

    // Chips de Canal
    els.channelChips.forEach((chip) => {
      chip.addEventListener('click', () => {
        els.channelChips.forEach((c) => c.classList.remove('active'));
        chip.classList.add('active');
        state.channel = chip.dataset.channel;
      });
    });

    // Colar da Área de Transferência
    els.btnPaste.addEventListener('click', async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          els.scamInput.value = text;
          els.scamInput.focus();
        }
      } catch (err) {
        els.scamInput.focus();
        alert('Toque e segure no campo de texto para colar o conteúdo copiado.');
      }
    });

    // Limpar
    els.btnClear.addEventListener('click', () => {
      els.scamInput.value = '';
      resetProfileCheckboxes();
      els.scamInput.focus();
    });

    // Exemplos Rápidos
    els.examplePills.forEach((pill) => {
      pill.addEventListener('click', () => {
        const key = pill.dataset.example;
        const ex = EXAMPLES[key];
        if (!ex) return;

        // Seleciona categoria
        els.catTabs.forEach((t) => {
          const isMatch = t.dataset.category === ex.category;
          t.classList.toggle('active', isMatch);
          t.setAttribute('aria-selected', isMatch ? 'true' : 'false');
        });
        state.category = ex.category;
        updateCategoryPrompts(ex.category);

        // Seleciona canal
        els.channelChips.forEach((c) => {
          c.classList.toggle('active', c.dataset.channel === ex.channel);
        });
        state.channel = ex.channel;

        resetProfileCheckboxes();
        if (ex.checks) {
          Object.keys(ex.checks).forEach((chkId) => {
            if (els[chkId]) els[chkId].checked = ex.checks[chkId];
          });
        }

        els.scamInput.value = ex.text;
        runFullAnalysis();
      });
    });

    // Botão Principal de Análise
    els.btnAnalyze.addEventListener('click', () => {
      runFullAnalysis();
    });

    // Compartilhar Alerta no WhatsApp
    els.btnShareWhatsapp.addEventListener('click', () => {
      if (!state.lastResult) return;
      const r = state.lastResult;
      const text = [
        `🛡️ *ALERTA ESCUDO DIGITAL*`,
        `Nível de Risco: *${r.score}% (${r.levelLabel})*`,
        `Categoria: ${r.threatCategory}`,
        `Diagnóstico: ${r.headline}`,
        ``,
        `Principais sinais:`,
        ...r.signals.slice(0, 3).map((s) => `• ${s.title}`),
        ``,
        `Recomendação: ${r.tips[0] ? r.tips[0].title + ' - ' + r.tips[0].desc : 'Não clique nem faça PIX sem confirmar em canal oficial.'}`
      ].join('\n');

      const url = `https://api.whatsapp.com/send?text=${encodeURIComponent(text)}`;
      window.open(url, '_blank', 'noopener,noreferrer');
    });

    // Copiar Diagnóstico
    els.btnCopyReport.addEventListener('click', async () => {
      if (!state.lastResult) return;
      const r = state.lastResult;
      const report = [
        `=== DIAGNÓSTICO ESCUDO DIGITAL ===`,
        `Risco Calculado: ${r.score}% (${r.levelLabel})`,
        `Classificação: ${r.threatCategory}`,
        `Resumo: ${r.headline}`,
        `Parecer da IA: ${r.aiVerdict}`,
        ``,
        `Sinais Identificados:`,
        ...r.signals.map((s) => `- ${s.title}: ${s.detail}`),
        ``,
        `Dicas de Prevenção:`,
        ...r.tips.map((t, i) => `${i + 1}. ${t.title}: ${t.desc}`)
      ].join('\n');

      try {
        await navigator.clipboard.writeText(report);
        els.copyReportText.textContent = 'Copiado com Sucesso!';
        setTimeout(() => {
          els.copyReportText.textContent = 'Copiar Diagnóstico';
        }, 2200);
      } catch (_) {
        alert('Não foi possível copiar automaticamente.');
      }
    });

    // Histórico
    els.btnClearHistory.addEventListener('click', () => {
      state.history = [];
      localStorage.removeItem('ed_history');
      renderHistory();
    });

    // Modal de IA
    const openModal = () => els.aiModal.classList.remove('hidden');
    const closeModal = () => els.aiModal.classList.add('hidden');
    els.btnOpenAiModal.addEventListener('click', openModal);
    els.btnMobAiSettings.addEventListener('click', openModal);
    els.btnCloseAiModal.addEventListener('click', closeModal);
    els.aiModal.addEventListener('click', (e) => {
      if (e.target === els.aiModal) closeModal();
    });

    els.btnSaveAiConfig.addEventListener('click', () => {
      state.aiConfig.mode = els.aiModeSelect.value;
      state.aiConfig.cfEndpoint = els.cfEndpointInput.value.trim() || '/api/analyze';
      state.aiConfig.geminiKey = els.geminiApiKeyInput.value.trim();

      localStorage.setItem('ed_ai_mode', state.aiConfig.mode);
      localStorage.setItem('ed_cf_endpoint', state.aiConfig.cfEndpoint);
      localStorage.setItem('ed_gemini_key', state.aiConfig.geminiKey);

      updateAiStatusBadge();
      closeModal();
    });
  }

  function updateCategoryPrompts(category) {
    if (category === 'profile') {
      els.profileExtraFields.classList.remove('hidden');
    } else {
      els.profileExtraFields.classList.add('hidden');
    }

    const labels = {
      auto: 'Cole aqui o link, mensagem, arroba (@) ou descrição da situação:',
      link: 'Cole o link (URL), endereço do site ou nome do arquivo suspeito:',
      chat: 'Cole o texto da conversa de WhatsApp, SMS, e-mail ou mensagem direta:',
      profile: 'Informe o @usuario da loja/perfil, texto da bio, oferta ou link divulgado:',
      pix: 'Descreva a cobrança PIX, código Copia e Cola, boleto ou proposta de renda extra:'
    };
    const placeholders = {
      auto: 'Ex: "Olá mãe, troquei de número e preciso pagar um boleto urgente..." ou http://site-suspeito.xyz/fatura.apk',
      link: 'Ex: https://rastreamento-correios-taxa.xyz/pagar ou Comprovante_Pix_2026.apk',
      chat: 'Ex: "CAIXA INFORMA: Seu CPF será bloqueado hoje. Acesse o link abaixo para atualizar seus dados..."',
      profile: 'Ex: "@loja_iphones_baratos_br - Vendendo iPhone 15 Pro novo por R$ 1.600 só no PIX antecipado..."',
      pix: 'Ex: "Pediram para eu fazer um PIX de R$ 99 para liberar um empréstimo / desbloquear comissão de tarefas..."'
    };

    els.inputLabel.textContent = labels[category] || labels.auto;
    els.scamInput.placeholder = placeholders[category] || placeholders.auto;
  }

  function resetProfileCheckboxes() {
    ['chkLowPrice', 'chkOnlyPix', 'chkClosedComments', 'chkRecentAccount', 'chkNoCnpj', 'chkPressuring'].forEach((id) => {
      if (els[id]) els[id].checked = false;
    });
  }

  function getSelectedProfileFlags() {
    return {
      lowPrice: els.chkLowPrice && els.chkLowPrice.checked,
      onlyPix: els.chkOnlyPix && els.chkOnlyPix.checked,
      closedComments: els.chkClosedComments && els.chkClosedComments.checked,
      recentAccount: els.chkRecentAccount && els.chkRecentAccount.checked,
      noCnpj: els.chkNoCnpj && els.chkNoCnpj.checked,
      pressuring: els.chkPressuring && els.chkPressuring.checked
    };
  }

  // ==========================================================================
  // MOTOR HEURÍSTICO DE CIBERSEGURANÇA (CAMADA 1 - INSTANTÂNEA)
  // ==========================================================================
  function analyzeHeuristics(rawText, category, channel, profileFlags) {
    const text = rawText.trim();
    const lower = text.toLowerCase();
    let score = 0;
    const signals = [];
    const entities = [];
    const detectedCategories = new Set();

    // 1. Extração de URLs e Domínios
    const urlRegex = /(?:https?:\/\/[^\s"'<>]+)|(?:\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|br|org|net|gov|edu|io|co|xyz|top|click|site|online|shop|vip|loan|win|icu|buzz|club|work|info|app|dev|me|ly|at|gy|ai|tk|ml|ga|cf)(?:\/[^\s"'<>]*)?)/gi;
    const rawUrls = text.match(urlRegex) || [];

    rawUrls.forEach((rawUrl) => {
      const cleanUrl = rawUrl.replace(/[.,;!?)]+$/, '');
      let parsedUrl = null;
      try {
        parsedUrl = new URL(cleanUrl.startsWith('http') ? cleanUrl : `http://${cleanUrl}`);
      } catch (_) {
        return;
      }

      const hostname = parsedUrl.hostname.toLowerCase().replace(/^www\./, '');
      const pathname = parsedUrl.pathname.toLowerCase();
      entities.push({ type: 'Link / Domínio', value: cleanUrl });

      // 1a. Verifica se usa HTTP sem criptografia explícito
      if (cleanUrl.toLowerCase().startsWith('http://')) {
        score += 18;
        signals.push({
          severity: 'warning',
          title: `Conexão sem criptografia segura (HTTP) em "${hostname}"`,
          detail: 'Sites legítimos de bancos, lojas e órgãos públicos utilizam HTTPS com certificado digital válido.'
        });
      }

      // 1b. Verifica endereço IP direto na URL
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
        score += 45;
        detectedCategories.add('Phishing / Servidor Oculto');
        signals.push({
          severity: 'danger',
          title: `Link aponta para um endereço IP numérico (${hostname})`,
          detail: 'Empresas reais usam nomes de domínio oficiais. Links com números de IP direto são típicos de servidores de phishing e malware.'
        });
      }

      // 1c. Verifica Encurtadores de Link
      if (URL_SHORTENERS.some((sh) => hostname === sh || hostname.endsWith(`.${sh}`))) {
        score += 25;
        detectedCategories.add('Link Encurtado / Destino Oculto');
        signals.push({
          severity: 'warning',
          title: `Uso de encurtador de link (${hostname})`,
          detail: 'Encurtadores escondem o verdadeiro endereço do site para impedir que você perceba que o domínio é falso antes de clicar.'
        });
      }

      // 1d. Verifica TLD Suspeito (.xyz, .top, .click, .site, etc.)
      const matchedTld = SUSPICIOUS_TLDS.find((tld) => hostname.endsWith(tld));
      if (matchedTld) {
        score += 38;
        detectedCategories.add('Domínio Suspeito / Phishing');
        signals.push({
          severity: 'danger',
          title: `Terminação de domínio de alto risco (${matchedTld}) em "${hostname}"`,
          detail: `Domínios terminados em "${matchedTld}" custam centavos e são descartáveis, sendo amplamente usados por golpistas para clonar sites.`
        });
      }

      // 1e. Verifica Falsificação de Marca (Typosquatting / Impersonation)
      let isOfficialDomain = false;
      OFFICIAL_BRANDS.forEach((brand) => {
        const matchesOfficial = brand.domains.some((d) => hostname === d || hostname.endsWith(`.${d}`));
        if (matchesOfficial) {
          isOfficialDomain = true;
        } else {
          // O nome da marca está no hostname ou caminho mas o domínio NÃO é o oficial!
          const mentionsBrandInHost = brand.keywords.some((kw) => hostname.includes(kw));
          if (mentionsBrandInHost) {
            score += 58;
            detectedCategories.add(`Site Falso Imitando ${brand.name}`);
            signals.push({
              severity: 'danger',
              title: `Falsificação de marca detectada: "${hostname}" NÃO é o site oficial de ${brand.name}`,
              detail: `O domínio usa o nome "${brand.name}" para enganar, mas o endereço oficial verdadeiro é ${brand.domains.join(' ou ')}.`
            });
          }
        }
      });

      // 1f. Excesso de hífens no domínio (ex: atendimento-seguro-cliente-br.com)
      const hyphenCount = (hostname.match(/-/g) || []).length;
      if (hyphenCount >= 2 && !isOfficialDomain) {
        score += 22;
        signals.push({
          severity: 'warning',
          title: `Domínio com múltiplos hífens artificiais ("${hostname}")`,
          detail: 'Golpistas combinam palavras separadas por hífens (como "-atendimento-", "-seguro-", "-taxa-") para simular páginas reais.'
        });
      }

      // 1g. Se for domínio oficial confirmado e sem parâmetros maliciosos
      if (isOfficialDomain && pathname.indexOf('.apk') === -1 && pathname.indexOf('.exe') === -1) {
        signals.push({
          severity: 'safe',
          title: `Domínio oficial verificado: "${hostname}"`,
          detail: 'O endereço principal pertence a uma instituição oficial conhecida. Ainda assim, nunca informe códigos de segurança a terceiros.'
        });
      }
    });

    // 2. Verifica Arquivos Maliciosos / Vírus (.apk, .exe, .scr, .bat, etc.)
    DANGEROUS_EXTENSIONS.forEach((item) => {
      const extRegex = new RegExp(`\\b[\\w-]+\\${item.ext}\\b|\\${item.ext}([?#/\\s]|$)`, 'i');
      if (extRegex.test(lower)) {
        score += item.risk;
        detectedCategories.add('Vírus / Aplicativo Malicioso (Malware)');
        entities.push({ type: 'Arquivo Detectado', value: item.ext.toUpperCase() });
        signals.push({
          severity: 'danger',
          title: `Risco Crítico de Vírus: ${item.label}`,
          detail: 'Arquivos com essa extensão podem instalar trojans bancários que leem suas senhas e assumem o controle remoto do seu celular ou computador.'
        });
      }
    });

    // 3. Verifica Padrões de Conversa, Engenharia Social e Fraude Financeira
    SCAM_PATTERNS.forEach((pattern) => {
      if (pattern.regex.test(text)) {
        score += pattern.weight;
        detectedCategories.add(pattern.category);
        signals.push({
          severity: pattern.weight >= 40 ? 'danger' : 'warning',
          title: pattern.title,
          detail: pattern.detail
        });
      }
    });

    // 4. Verifica Sinais de Perfil / Loja em Rede Social (Checkboxes + Texto)
    const handleMatch = text.match(/@[a-zA-Z0-9._]{3,30}/g);
    if (handleMatch) {
      handleMatch.forEach((h) => entities.push({ type: 'Perfil Social', value: h }));
    }

    if (profileFlags.lowPrice) {
      score += 32;
      detectedCategories.add('Loja Falsa em Rede Social');
      signals.push({
        severity: 'danger',
        title: 'Preço muito abaixo do valor real de mercado (+50% de desconto)',
        detail: 'Produtos de alta procura (como iPhones, consoles e eletrodomésticos) vendidos pela metade do preço em redes sociais são a principal isca de lojas fantasmas.'
      });
    }
    if (profileFlags.onlyPix) {
      score += 30;
      detectedCategories.add('Risco de Pagamento Sem Garantia');
      signals.push({
        severity: 'danger',
        title: 'Exigência de pagamento exclusivo via PIX antecipado',
        detail: 'Lojas fraudulentas recusam cartão de crédito ou plataformas com proteção ao comprador porque o PIX cai na hora e é sacado rapidamente.'
      });
    }
    if (profileFlags.closedComments) {
      score += 24;
      signals.push({
        severity: 'warning',
        title: 'Comentários desativados ou restritos nas publicações',
        detail: 'Perfis golpistas bloqueiam comentários nas fotos para impedir que vítimas anteriores alertem novos compradores sobre o golpe.'
      });
    }
    if (profileFlags.recentAccount) {
      score += 22;
      signals.push({
        severity: 'warning',
        title: 'Conta recém-criada ou que já mudou de @nome várias vezes',
        detail: 'Golpistas compram perfis antigos ou trocam o nome da loja a cada semana após aplicarem golpes.'
      });
    }
    if (profileFlags.noCnpj) {
      score += 18;
      signals.push({
        severity: 'warning',
        title: 'Ausência de CNPJ verificável e endereço físico real',
        detail: 'Todo comércio eletrônico legalizado no Brasil deve informar CNPJ ativo e canais formais de atendimento.'
      });
    }
    if (profileFlags.pressuring) {
      score += 18;
      signals.push({
        severity: 'warning',
        title: 'Vendedor pressionando para pagamento imediato',
        detail: 'Frases como "só tenho mais um e tem outra pessoa querendo pagar agora" servem para impedir que você pesquise a reputação da loja.'
      });
    }

    // 5. Detecção de Chave PIX / Código PIX Copia e Cola
    if (/000201[0-9a-zA-Z]{20,}/i.test(text)) {
      entities.push({ type: 'Código PIX', value: 'Payload PIX Copia e Cola detectado' });
      score += 15;
      signals.push({
        severity: 'warning',
        title: 'Código "PIX Copia e Cola" identificado na mensagem',
        detail: 'Ao colar um código PIX no banco, confira sempre o NOME COMPLETO e o CNPJ/CPF do destinatário na tela antes de digitar sua senha.'
      });
    }

    // Normaliza Score entre 5% e 99%
    if (signals.length === 0) {
      score = 8;
      signals.push({
        severity: 'safe',
        title: 'Nenhum padrão explícito de golpe ou arquivo malicioso detectado',
        detail: 'Não encontramos links falsos conhecidos nem gatilhos clássicos de engenharia social neste trecho, mas mantenha sempre a cautela ao transferir valores.'
      });
    } else if (signals.every((s) => s.severity === 'safe')) {
      score = 5;
    } else {
      score = Math.min(99, Math.max(18, score));
    }

    // Determina Nível de Risco
    let level = 'safe';
    let levelLabel = 'BAIXO RISCO';
    let headline = 'Aparentemente seguro, mas mantenha os cuidados básicos.';
    let subheadline = 'Não identificamos armadilhas diretas, porém sempre confira o destinatário antes de pagar.';

    if (score >= 60) {
      level = 'high';
      levelLabel = 'ALTO RISCO • PROVÁVEL GOLPE!';
      headline = 'Perigo! Forte indício de golpe ou arquivo malicioso.';
      subheadline = 'Pare agora: não clique em links, não baixe arquivos e não faça nenhum PIX ou transferência.';
    } else if (score >= 25) {
      level = 'warn';
      levelLabel = 'ATENÇÃO • SINAIS SUSPEITOS';
      headline = 'Cuidado! Encontramos elementos suspeitos que exigem verificação.';
      subheadline = 'Confirme a veracidade por um canal oficial independente antes de prosseguir.';
    }

    const threatCategory =
      detectedCategories.size > 0
        ? Array.from(detectedCategories).slice(0, 2).join(' • ')
        : score >= 25
        ? 'Alerta de Segurança'
        : 'Verificação Preventiva';

    const tips = buildPersonalizedTips(score, Array.from(detectedCategories), rawUrls.length > 0, channel);
    const localAiVerdict = buildContextualAiNarrative(score, threatCategory, signals, channel, entities);

    return {
      score,
      level,
      levelLabel,
      threatCategory,
      headline,
      subheadline,
      signals,
      entities,
      tips,
      aiVerdict: localAiVerdict,
      aiEngineName: 'IA Contextual Embarcada (Escudo Neural)'
    };
  }

  // --- Gerador de Dicas e Sugestões Personalizadas de Prevenção ---
  function buildPersonalizedTips(score, categories, hasUrls, channel) {
    const tips = [];
    const catStr = categories.join(' ').toLowerCase();

    if (catStr.includes('vírus') || catStr.includes('malware') || catStr.includes('remoto')) {
      tips.push({
        title: 'Jamais instale arquivos .APK ou programas fora da loja oficial',
        desc: 'Bancos e órgãos do governo nunca enviam arquivos de atualização por WhatsApp, SMS ou e-mail. Só instale apps pela Google Play Store ou Apple App Store.'
      });
      tips.push({
        title: 'Se já baixou o arquivo, não abra e ative o Modo Avião',
        desc: 'Apague o arquivo da pasta "Downloads" imediatamente. Se chegou a instalar, desconecte o celular da internet (Modo Avião) e remova o aplicativo.'
      });
    }

    if (catStr.includes('parente') || catStr.includes('novo número') || channel === 'WhatsApp') {
      tips.push({
        title: 'Faça uma chamada de voz ou vídeo para o número antigo',
        desc: 'Golpistas sempre inventam uma desculpa para não atender ligações ("microfone quebrado"). Ligue para o número antigo do familiar para confirmar.'
      });
    }

    if (catStr.includes('banco') || catStr.includes('central')) {
      tips.push({
        title: 'Abra o aplicativo oficial do seu banco diretamente',
        desc: 'Nunca use links ou números 0800 enviados por SMS. Entre no app oficial do seu banco e verifique sua fatura ou extrato lá dentro.'
      });
    }

    if (catStr.includes('alfândega') || catStr.includes('correios')) {
      tips.push({
        title: 'Consulte encomendas apenas no app oficial dos Correios',
        desc: 'Para saber se existe taxa alfandegária real, acesse o portal "Minhas Importações" digitando você mesmo correios.com.br no navegador.'
      });
    }

    if (catStr.includes('loja') || channel === 'Instagram / TikTok') {
      tips.push({
        title: 'Investigue o histórico do perfil e pesquise no Reclame Aqui',
        desc: 'No Instagram, toque nos 3 pontinhos do perfil → "Sobre esta conta" → veja a data de criação e se o perfil trocou de nome várias vezes.'
      });
      tips.push({
        title: 'Prefira plataformas com garantia de entrega (Mercado Pago, Shopee, Cartão)',
        desc: 'Evite transferir PIX direto para contas de pessoas físicas desconhecidas ao comprar pela internet.'
      });
    }

    if (catStr.includes('clonagem') || catStr.includes('6 dígitos')) {
      tips.push({
        title: 'Ative a Confirmação em Duas Etapas (PIN) no WhatsApp e Instagram',
        desc: 'Vá em Configurações → Conta → Confirmação em duas etapas e crie uma senha de 6 dígitos que só você saiba.'
      });
    }

    if (hasUrls) {
      tips.push({
        title: 'Confira o domínio principal antes da primeira barra (/)',
        desc: 'Em um link como "nubank.atendimento-br.xyz/login", o dono real do site é "atendimento-br.xyz" e não o Nubank.'
      });
    }

    // Dicas gerais essenciais sempre presentes
    tips.push({
      title: 'Confira o nome e CPF/CNPJ na tela de confirmação do PIX',
      desc: 'Se uma loja famosa ou órgão público pedir um PIX e o destinatário aparecer em nome de uma Pessoa Física desconhecida, cancele na hora!'
    });

    tips.push({
      title: 'Desconfie sempre de pressa extrema ou lucro fácil',
      desc: 'A pressa é a maior arma do golpista. Qualquer oferta ou cobrança legítima permite que você pare por 10 minutos para checar a fonte.'
    });

    return tips.slice(0, 5);
  }

  // --- Sintetizador Contextual de IA Local (Garante resposta rica mesmo offline / GitHub Pages) ---
  function buildContextualAiNarrative(score, threatCategory, signals, channel, entities) {
    const dangerSignals = signals.filter((s) => s.severity === 'danger');
    const warnSignals = signals.filter((s) => s.severity === 'warning');

    if (score >= 60) {
      const mainReasons = dangerSignals.map((s) => s.title.toLowerCase()).slice(0, 2).join(' e ');
      return `Análise de alta criticidade (${score}% de risco): O conteúdo recebido via ${channel} apresenta assinatura característica de "${threatCategory}". Os indicadores mais graves são: ${mainReasons || 'manipulação psicológica combinada com solicitação financeira'}. A recomendação técnica é interromper qualquer contato imediatamente, bloquear o remetente e não fornecer dados pessoais, códigos ou transferências.`;
    }

    if (score >= 25) {
      const reasons = [...dangerSignals, ...warnSignals].map((s) => s.title.toLowerCase()).slice(0, 2).join(' e ');
      return `Análise de cautela (${score}% de risco): Foram detectados sinais de alerta (${reasons}) no contexto de ${channel}. Embora possa não conter um vírus direto, esse formato é frequentemente usado em engenharia social para testar a vítima antes de pedir um PIX ou dados sensíveis. Valide a informação por fora (ligando ou acessando o site oficial manualmente).`;
    }

    return `Análise concluída com baixo risco aparente (${score}%): Não foram detectados domínios clonados, arquivos executáveis maliciosos (.APK/.EXE) ou roteiros clássicos de extorsão/phishing. Ainda assim, lembre-se de nunca compartilhar códigos de verificação recebidos por SMS e sempre conferir o titular antes de confirmar pagamentos.`;
  }

  // ==========================================================================
  // CAMADA 2: INTEGRAÇÃO COM IA GENERATIVA (CLOUDFLARE WORKERS AI / GEMINI API)
  // ==========================================================================
  async function queryExternalAI(rawText, category, channel, heuristicResult) {
    const mode = state.aiConfig.mode;
    if (mode === 'local') return null;

    // 1. Tenta Cloudflare Pages Function / Worker Endpoint (/api/analyze)
    if (mode === 'cloudflare' || mode === 'auto') {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 6500);
        const res = await fetch(state.aiConfig.cfEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            text: rawText,
            category,
            channel,
            heuristicScore: heuristicResult.score
          }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (res.ok) {
          const data = await res.json();
          if (data && data.aiVerdict) {
            return {
              aiVerdict: data.aiVerdict,
              aiScore: typeof data.riskScore === 'number' ? data.riskScore : null,
              extraTip: data.extraTip || null,
              engineName: data.engine || 'Cloudflare Workers AI'
            };
          }
        }
      } catch (_) {
        // Silenciosamente passa para o próximo motor (ex: se estiver no GitHub Pages sem backend)
      }
    }

    // 2. Tenta Google Gemini API Direta (se o usuário configurou uma chave)
    if ((mode === 'gemini' || mode === 'auto') && state.aiConfig.geminiKey) {
      try {
        const prompt = `Você é um especialista brasileiro em cibersegurança e prevenção a fraudes financeiras (Escudo Digital).
Analise o seguinte conteúdo recebido pelo usuário no canal "${channel}" (categoria: ${category}):
"""
${rawText}
"""
O motor heurístico preliminar calculou ${heuristicResult.score}% de risco (${heuristicResult.threatCategory}).
Responda ESTRITAMENTE em JSON válido com as chaves:
{
  "riskScore": (número de 0 a 100),
  "aiVerdict": "(explicação clara, amigável e direta em português de até 3 frases sobre por que é ou não golpe/vírus)",
  "extraTip": { "title": "(título curto de uma dica prática)", "desc": "(descrição prática de como se prevenir)" }
}`;

        const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${encodeURIComponent(state.aiConfig.geminiKey)}`;
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: { responseMimeType: 'application/json', temperature: 0.2 }
          })
        });

        if (res.ok) {
          const json = await res.json();
          const rawReply = json?.candidates?.[0]?.content?.parts?.[0]?.text;
          if (rawReply) {
            const parsed = JSON.parse(rawReply);
            return {
              aiVerdict: parsed.aiVerdict,
              aiScore: typeof parsed.riskScore === 'number' ? parsed.riskScore : null,
              extraTip: parsed.extraTip || null,
              engineName: 'Google Gemini AI'
            };
          }
        }
      } catch (_) {
        // Fallback para o motor híbrido local
      }
    }

    return null;
  }

  // ==========================================================================
  // ORQUESTRADOR DE ANÁLISE E RENDERIZAÇÃO NA INTERFACE
  // ==========================================================================
  async function runFullAnalysis() {
    const rawText = els.scamInput.value.trim();
    const profileFlags = getSelectedProfileFlags();
    const hasAnyCheckbox = Object.values(profileFlags).some(Boolean);

    if (!rawText && !hasAnyCheckbox) {
      els.scamInput.focus();
      els.scamInput.placeholder = '⚠️ Por favor, digite ou cole um link, mensagem ou descrição para analisar...';
      return;
    }

    // Mostra estado de carregamento
    els.emptyState.classList.add('hidden');
    els.resultContent.classList.add('hidden');
    els.loadingState.classList.remove('hidden');

    // Rola suavemente para o resultado em telas de celular
    if (window.innerWidth < 960) {
      document.getElementById('secResults').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // Executa análise heurística imediata
    const result = analyzeHeuristics(rawText, state.category, state.channel, profileFlags);

    // Pequeno delay visual + consulta opcional de IA externa
    const [aiResponse] = await Promise.all([
      queryExternalAI(rawText, state.category, state.channel, result),
      new Promise((resolve) => setTimeout(resolve, 450))
    ]);

    if (aiResponse) {
      result.aiVerdict = aiResponse.aiVerdict;
      result.aiEngineName = aiResponse.engineName;
      if (aiResponse.aiScore !== null) {
        // Combina score heurístico com score da IA (mantendo segurança máxima)
        result.score = Math.round(Math.max(result.score, (result.score * 0.5) + (aiResponse.aiScore * 0.5)));
      }
      if (aiResponse.extraTip && aiResponse.extraTip.title) {
        result.tips.unshift(aiResponse.extraTip);
      }
    }

    state.lastResult = result;
    saveToHistory(rawText || 'Análise de Perfil / Loja Social', result);

    els.loadingState.classList.add('hidden');
    renderResult(result);
  }

  function renderResult(r) {
    els.resultContent.classList.remove('hidden');

    // 1. Atualiza Banner de Risco e Gauge Circular
    els.riskBanner.className = `risk-banner risk-${r.level}`;
    els.riskPercent.textContent = `${r.score}%`;
    els.riskLevelBadge.textContent = r.levelLabel;
    els.threatCategoryBadge.textContent = r.threatCategory;
    els.resultHeadline.textContent = r.headline;
    els.resultSubheadline.textContent = r.subheadline;

    const circumference = 314.16;
    const offset = circumference - (r.score / 100) * circumference;
    els.gaugeProgress.style.strokeDashoffset = `${offset}`;

    // 2. Parecer da IA
    els.aiEngineBadge.textContent = r.aiEngineName;
    els.aiVerdictText.textContent = r.aiVerdict;

    // 3. Elementos Técnicos Extraídos (Links, Arquivos, @perfis)
    if (r.entities && r.entities.length > 0) {
      els.extractedEntitiesBox.classList.remove('hidden');
      els.entitiesList.innerHTML = '';
      r.entities.forEach((ent) => {
        const div = document.createElement('div');
        div.className = 'entity-item';
        const spanType = document.createElement('strong');
        spanType.textContent = ent.type + ':';
        const codeVal = document.createElement('code');
        codeVal.textContent = ent.value;
        div.appendChild(spanType);
        div.appendChild(codeVal);
        els.entitiesList.appendChild(div);
      });
    } else {
      els.extractedEntitiesBox.classList.add('hidden');
    }

    // 4. Lista de Sinais e Evidências
    els.signalsList.innerHTML = '';
    r.signals.forEach((sig) => {
      const li = document.createElement('li');
      li.className = `signal-item signal-${sig.severity}`;
      const iconMap = { danger: '🚨', warning: '⚠️', safe: '✅' };

      const iconSpan = document.createElement('span');
      iconSpan.className = 'signal-icon';
      iconSpan.textContent = iconMap[sig.severity] || '⚠️';

      const textDiv = document.createElement('div');
      textDiv.className = 'signal-text';
      const strong = document.createElement('strong');
      strong.textContent = sig.title;
      const desc = document.createElement('span');
      desc.textContent = sig.detail;

      textDiv.appendChild(strong);
      textDiv.appendChild(desc);
      li.appendChild(iconSpan);
      li.appendChild(textDiv);
      els.signalsList.appendChild(li);
    });

    // 5. Dicas Personalizadas de Prevenção
    els.preventionTipsList.innerHTML = '';
    r.tips.forEach((tip, index) => {
      const card = document.createElement('div');
      card.className = 'tip-card';

      const num = document.createElement('span');
      num.className = 'tip-num';
      num.textContent = `${index + 1}`;

      const body = document.createElement('div');
      body.className = 'tip-body';
      const strong = document.createElement('strong');
      strong.textContent = tip.title;
      const p = document.createElement('p');
      p.textContent = tip.desc;

      body.appendChild(strong);
      body.appendChild(p);
      card.appendChild(num);
      card.appendChild(body);
      els.preventionTipsList.appendChild(card);
    });
  }

  // --- Histórico Local ---
  function saveToHistory(inputSnippet, result) {
    const item = {
      id: Date.now(),
      snippet: inputSnippet.slice(0, 90),
      score: result.score,
      level: result.level,
      category: result.threatCategory,
      time: new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })
    };
    state.history.unshift(item);
    state.history = state.history.slice(0, 6);
    localStorage.setItem('ed_history', JSON.stringify(state.history));
    renderHistory();
  }

  function renderHistory() {
    if (!state.history || state.history.length === 0) {
      els.historyList.innerHTML = '<p class="history-empty">Nenhuma verificação realizada ainda nesta sessão.</p>';
      return;
    }

    els.historyList.innerHTML = '';
    state.history.forEach((item) => {
      const row = document.createElement('div');
      row.className = 'history-row';
      row.title = 'Clique para carregar novamente no analisador';

      const snippet = document.createElement('span');
      snippet.className = 'history-snippet';
      snippet.textContent = item.snippet;

      const meta = document.createElement('div');
      meta.className = 'history-meta';

      const badge = document.createElement('span');
      badge.className = 'category-badge';
      badge.textContent = `${item.score}% Risco • ${item.time}`;

      meta.appendChild(badge);
      row.appendChild(snippet);
      row.appendChild(meta);

      row.addEventListener('click', () => {
        els.scamInput.value = item.snippet;
        runFullAnalysis();
      });

      els.historyList.appendChild(row);
    });
  }

  document.addEventListener('DOMContentLoaded', init);
})();
