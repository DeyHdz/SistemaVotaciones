// Configuración de Supabase (opcional - ahora funciona sin servidor)
const projectId = 'TU_PROJECT_ID';
const publicAnonKey = 'TU_ANON_KEY';

// Estado de la aplicación
let accessToken = null;
let user = null;
let polls = [];

// Datos de prueba para desarrollo
const DEMO_MODE = true; // Cambiar a false cuando tengas Supabase configurado

// Inicializar la aplicación
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
    setupEventListeners();
});

function initializeApp() {
    // Simular carga
    setTimeout(() => {
        checkSession();
    }, 800);
}

function setupEventListeners() {
    // Autenticación
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    document.getElementById('signup-form').addEventListener('submit', handleSignup);
    document.getElementById('show-signup').addEventListener('click', showSignupForm);
    document.getElementById('show-login').addEventListener('click', showLoginForm);
    document.getElementById('logout-btn').addEventListener('click', handleLogout);

    // Votaciones
    document.getElementById('create-poll-btn').addEventListener('click', openCreateModal);
    document.getElementById('create-poll-form').addEventListener('submit', handleCreatePoll);
    document.getElementById('add-option-btn').addEventListener('click', addOptionInput);

    // Inicializar opciones del formulario
    addOptionInput();
    addOptionInput();
}

function checkSession() {
    const storedToken = localStorage.getItem('access_token');
    const storedUser = localStorage.getItem('user');

    if (storedToken && storedUser) {
        accessToken = storedToken;
        user = JSON.parse(storedUser);
        showMainApp();
        fetchPolls();
    } else {
        showAuthForm();
    }
}

async function handleLogin(e) {
    e.preventDefault();
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;

    if (DEMO_MODE) {
        // Modo demostración - login instantáneo
        accessToken = 'demo_token_' + Date.now();
        user = {
            email: email,
            user_metadata: { name: email.split('@')[0] }
        };

        localStorage.setItem('access_token', accessToken);
        localStorage.setItem('user', JSON.stringify(user));

        showMainApp();
        fetchPolls();
        return;
    }

    try {
        const response = await fetch(
            `https://${projectId}.supabase.co/functions/v1/make-server-f8ad8275/login`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${publicAnonKey}`,
                },
                body: JSON.stringify({ email, password }),
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Error al iniciar sesión');
        }

        accessToken = data.access_token;
        user = data.user;

        localStorage.setItem('access_token', accessToken);
        localStorage.setItem('user', JSON.stringify(user));

        showMainApp();
        fetchPolls();
    } catch (error) {
        alert(error.message);
    }
}

async function handleSignup(e) {
    e.preventDefault();
    const name = document.getElementById('signup-name').value;
    const email = document.getElementById('signup-email').value;
    const password = document.getElementById('signup-password').value;

    if (DEMO_MODE) {
        // Modo demostración - registro instantáneo
        accessToken = 'demo_token_' + Date.now();
        user = {
            email: email,
            user_metadata: { name: name }
        };

        localStorage.setItem('access_token', accessToken);
        localStorage.setItem('user', JSON.stringify(user));

        showMainApp();
        fetchPolls();
        return;
    }

    try {
        const response = await fetch(
            `https://${projectId}.supabase.co/functions/v1/make-server-f8ad8275/signup`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${publicAnonKey}`,
                },
                body: JSON.stringify({ email, password, name }),
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Error al crear cuenta');
        }

        // Auto login después del registro
        document.getElementById('login-email').value = email;
        document.getElementById('login-password').value = password;
        showLoginForm(new Event('click'));
        await handleLogin(e);
    } catch (error) {
        alert(error.message);
    }
}

function handleLogout() {
    accessToken = null;
    user = null;
    polls = [];
    localStorage.removeItem('access_token');
    localStorage.removeItem('user');
    localStorage.removeItem('demo_polls'); // Limpiar votaciones de demostración
    showAuthForm();
}

async function fetchPolls() {
    if (DEMO_MODE) {
        // Cargar votaciones de demostración desde localStorage
        const storedPolls = localStorage.getItem('demo_polls');
        if (storedPolls) {
            polls = JSON.parse(storedPolls);
        } else {
            // Votaciones de ejemplo iniciales
            polls = [
                {
                    id: 'poll_1',
                    title: '¿Cuál es tu lenguaje de programación favorito?',
                    options: [
                        { text: 'JavaScript', votes: 5 },
                        { text: 'Python', votes: 8 },
                        { text: 'Java', votes: 3 },
                        { text: 'C++', votes: 2 }
                    ],
                    hasVoted: false,
                    userVote: null
                },
                {
                    id: 'poll_2',
                    title: '¿Prefieres trabajo remoto o presencial?',
                    options: [
                        { text: 'Remoto', votes: 12 },
                        { text: 'Presencial', votes: 4 },
                        { text: 'Híbrido', votes: 9 }
                    ],
                    hasVoted: false,
                    userVote: null
                }
            ];
        }
        renderPolls();
        return;
    }

    try {
        const response = await fetch(
            `https://${projectId}.supabase.co/functions/v1/make-server-f8ad8275/get-polls`,
            {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                },
            }
        );

        if (!response.ok) {
            throw new Error('Error al obtener votaciones');
        }

        const data = await response.json();
        polls = data.polls;
        renderPolls();
    } catch (error) {
        console.error('Error fetching polls:', error);
    }
}

function renderPolls() {
    const container = document.getElementById('polls-container');
    const emptyState = document.getElementById('empty-state');

    if (polls.length === 0) {
        container.innerHTML = '';
        emptyState.classList.remove('hidden');
        return;
    }

    emptyState.classList.add('hidden');
    container.innerHTML = polls.map(poll => createPollCard(poll)).join('');

    // Agregar event listeners para votar
    polls.forEach(poll => {
        if (!poll.hasVoted) {
            poll.options.forEach((option, index) => {
                const btn = document.querySelector(`[data-poll="${poll.id}"][data-option="${index}"]`);
                if (btn) {
                    btn.addEventListener('click', () => handleVote(poll.id, index));
                }
            });
        }

        // Event listener para ver resultados
        const resultsBtn = document.getElementById(`results-${poll.id}`);
        if (resultsBtn) {
            resultsBtn.addEventListener('click', () => showResults(poll));
        }
    });
}

function createPollCard(poll) {
    const totalVotes = poll.options.reduce((sum, opt) => sum + opt.votes, 0);

    const optionsHtml = poll.options.map((option, index) => {
        if (poll.hasVoted) {
            const percentage = totalVotes > 0 ? (option.votes / totalVotes * 100).toFixed(1) : 0;
            const isUserVote = poll.userVote === index;
            return `
                <div class="poll-option voted" style="--percentage: ${percentage}%">
                    <button data-percentage="${percentage}%" disabled style="background: linear-gradient(90deg, ${isUserVote ? '#3b82f6' : '#e5e7eb'} ${percentage}%, #f9fafb ${percentage}%);">
                        ${option.text} ${isUserVote ? '✓' : ''}
                    </button>
                </div>
            `;
        } else {
            return `
                <div class="poll-option">
                    <button data-poll="${poll.id}" data-option="${index}">
                        ${option.text}
                    </button>
                </div>
            `;
        }
    }).join('');

    return `
        <div class="poll-card">
            <h3>${poll.title}</h3>
            ${optionsHtml}
            <div class="poll-footer">
                <span class="vote-count">${totalVotes} voto${totalVotes !== 1 ? 's' : ''}</span>
                <button class="btn-results" id="results-${poll.id}">Ver Resultados</button>
            </div>
        </div>
    `;
}

async function handleVote(pollId, optionIndex) {
    if (DEMO_MODE) {
        // Modo demostración - actualizar votación localmente
        const poll = polls.find(p => p.id === pollId);
        if (poll && !poll.hasVoted) {
            poll.options[optionIndex].votes++;
            poll.hasVoted = true;
            poll.userVote = optionIndex;
            localStorage.setItem('demo_polls', JSON.stringify(polls));
            renderPolls();
        }
        return;
    }

    try {
        const response = await fetch(
            `https://${projectId}.supabase.co/functions/v1/make-server-f8ad8275/vote`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${accessToken}`,
                },
                body: JSON.stringify({ pollId, optionIndex }),
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Error al votar');
        }

        await fetchPolls();
    } catch (error) {
        alert(error.message);
    }
}

async function handleCreatePoll(e) {
    e.preventDefault();
    
    const title = document.getElementById('poll-title').value;
    const optionInputs = document.querySelectorAll('.option-input');
    const options = Array.from(optionInputs)
        .map(input => input.value.trim())
        .filter(value => value !== '');

    if (options.length < 2) {
        alert('Debes agregar al menos 2 opciones');
        return;
    }

    if (DEMO_MODE) {
        // Modo demostración - crear votación localmente
        const newPoll = {
            id: 'poll_' + Date.now(),
            title: title,
            options: options.map(text => ({ text, votes: 0 })),
            hasVoted: false,
            userVote: null
        };
        polls.unshift(newPoll);
        localStorage.setItem('demo_polls', JSON.stringify(polls));
        closeCreateModal();
        renderPolls();
        return;
    }

    try {
        const response = await fetch(
            `https://${projectId}.supabase.co/functions/v1/make-server-f8ad8275/create-poll`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${accessToken}`,
                },
                body: JSON.stringify({ title, options }),
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Error al crear votación');
        }

        closeCreateModal();
        await fetchPolls();
    } catch (error) {
        alert(error.message);
    }
}

function addOptionInput() {
    const container = document.getElementById('options-container');
    const optionCount = container.querySelectorAll('.option-input').length + 1;
    
    const wrapper = document.createElement('div');
    wrapper.className = 'option-input-wrapper';
    wrapper.innerHTML = `
        <input type="text" class="option-input" placeholder="Opción ${optionCount}" required>
        <button type="button" class="btn-remove-option" onclick="removeOptionInput(this)">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
        </button>
    `;
    
    container.appendChild(wrapper);
}

function removeOptionInput(button) {
    const container = document.getElementById('options-container');
    if (container.querySelectorAll('.option-input-wrapper').length > 2) {
        button.parentElement.remove();
    } else {
        alert('Debes tener al menos 2 opciones');
    }
}

function openCreateModal() {
    document.getElementById('create-modal').classList.remove('hidden');
}

function closeCreateModal() {
    document.getElementById('create-modal').classList.add('hidden');
    document.getElementById('create-poll-form').reset();
    const container = document.getElementById('options-container');
    container.innerHTML = '';
    addOptionInput();
    addOptionInput();
}

function showResults(poll) {
    const modal = document.getElementById('results-modal');
    const title = document.getElementById('results-title');
    const content = document.getElementById('results-content');

    title.textContent = poll.title;

    const totalVotes = poll.options.reduce((sum, opt) => sum + opt.votes, 0);

    content.innerHTML = poll.options.map((option, index) => {
        const percentage = totalVotes > 0 ? (option.votes / totalVotes * 100).toFixed(1) : 0;
        const isUserVote = poll.userVote === index;
        
        return `
            <div class="result-item">
                <div class="result-label">
                    <span>${option.text} ${isUserVote ? '✓' : ''}</span>
                    <span>${percentage}%</span>
                </div>
                <div class="result-bar-container">
                    <div class="result-bar" style="width: ${percentage}%">
                        ${option.votes} voto${option.votes !== 1 ? 's' : ''}
                    </div>
                </div>
                <div class="result-votes">${option.votes} de ${totalVotes} votos</div>
            </div>
        `;
    }).join('');

    modal.classList.remove('hidden');
}

function closeResultsModal() {
    document.getElementById('results-modal').classList.add('hidden');
}

function showAuthForm() {
    document.getElementById('loading-screen').classList.add('hidden');
    document.getElementById('auth-form').classList.remove('hidden');
    document.getElementById('main-app').classList.add('hidden');
}

function showMainApp() {
    document.getElementById('loading-screen').classList.add('hidden');
    document.getElementById('auth-form').classList.add('hidden');
    document.getElementById('main-app').classList.remove('hidden');
    
    const userName = user?.user_metadata?.name || user?.email;
    document.getElementById('user-welcome').textContent = `Bienvenido, ${userName}`;
}

function showSignupForm(e) {
    e.preventDefault();
    const loginCard = document.getElementById('login-form').closest('.auth-card');
    const signupCard = document.getElementById('signup-card');
    
    loginCard.classList.add('hidden');
    signupCard.classList.remove('hidden');
}

function showLoginForm(e) {
    e.preventDefault();
    const loginCard = document.getElementById('login-form').closest('.auth-card');
    const signupCard = document.getElementById('signup-card');
    
    signupCard.classList.add('hidden');
    loginCard.classList.remove('hidden');
}

// Cerrar modales al hacer clic en el overlay
document.addEventListener('click', (e) => {
    if (e.target.classList.contains('modal-overlay')) {
        closeCreateModal();
        closeResultsModal();
    }
});