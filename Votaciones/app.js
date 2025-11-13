let user = null;
let privateKey = null;
let polls = [];

document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
    setupEventListeners();
});

function initializeApp() {
    setTimeout(() => {
        checkSession();
    }, 800);
}

function setupEventListeners() {
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    document.getElementById('signup-form').addEventListener('submit', handleSignup);
    document.getElementById('show-signup').addEventListener('click', showSignupForm);
    document.getElementById('show-login').addEventListener('click', showLoginForm);
    document.getElementById('logout-btn').addEventListener('click', handleLogout);

    document.getElementById('create-poll-btn').addEventListener('click', openCreateModal);
    document.getElementById('create-poll-form').addEventListener('submit', handleCreatePoll);
    document.getElementById('add-option-btn').addEventListener('click', addOptionInput);

    const createModal = document.getElementById('create-modal');
    createModal.querySelector('.modal-close').addEventListener('click', closeCreateModal);
    createModal.querySelector('.modal-footer .btn-secondary').addEventListener('click', closeCreateModal);
    createModal.querySelector('.modal-overlay').addEventListener('click', closeCreateModal);

    document.getElementById('results-modal').addEventListener('click', (e) => {
        if (e.target.classList.contains('modal-overlay') || e.target.closest('.modal-close')) {
            closeResultsModal();
        }
    });

    addOptionInput();
    addOptionInput();
}

function checkSession() {
    showAuthForm();
}

async function handleSignup(e) {
    e.preventDefault();

    const name = document.getElementById('signup-name').value;
    const email = document.getElementById('signup-email').value;
    const password = document.getElementById('signup-password').value;

    try {
        const keyPair = await forge.pki.rsa.generateKeyPair({ bits: 2048 });
        const publicKeyPem = forge.pki.publicKeyToPem(keyPair.publicKey);
        const privateKeyPemEncrypted = forge.pki.encryptRsaPrivateKey(keyPair.privateKey, password);

        const response = await fetch('/registrar', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: name,
                email: email,
                public_key_pem: publicKeyPem
            })
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || 'Error al registrar en el servidor.');
        }

        localStorage.setItem(`private_key_pem_${email}`, privateKeyPemEncrypted);
        localStorage.setItem(`user_name_${email}`, name);
        
        alert('¡Registro exitoso! Por favor, inicia sesión.');
        showLoginForm(new Event('click'));

    } catch (err) {
        alert("Error al registrar: " + err.message);
    }
}

async function handleLogin(e) {
    e.preventDefault();

    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;

    try {
        const encryptedPem = localStorage.getItem(`private_key_pem_${email}`);
        if (!encryptedPem) throw new Error("Usuario no encontrado.");

        let decryptedKey;
        try {
            decryptedKey = forge.pki.decryptRsaPrivateKey(encryptedPem, password);
        } catch {
            throw new Error("Contraseña incorrecta.");
        }

        if (!decryptedKey) throw new Error("Contraseña incorrecta.");

        privateKey = decryptedKey;
        user = {
            name: localStorage.getItem(`user_name_${email}`) || email.split('@')[0],
            email: email
        };

        showMainApp();
        fetchPolls();

    } catch (err) {
        alert("Error al iniciar sesión: " + err.message);
    }
}

async function handleCreatePoll(e) {
    e.preventDefault();

    if (!privateKey || !user) {
        alert("Error: Sesión no válida.");
        handleLogout();
        return;
    }

    const title = document.getElementById('poll-title').value;
    const optionInputs = document.querySelectorAll('#options-container .option-input');
    const options = Array.from(optionInputs)
        .map(input => input.value.trim())
        .filter(value => value !== '');

    if (options.length < 2) {
        alert("Debes agregar al menos 2 opciones");
        return;
    }

    const pollData = {
        pregunta: title,
        opciones: options,
        id_encuesta: `enc-${Date.now()}`
    };

    const pollDataBytes = JSON.stringify(pollData, Object.keys(pollData).sort());

    try {
        const md = forge.md.sha256.create();
        md.update(pollDataBytes, 'utf8');

        const signatureBytes = privateKey.sign(md);
        const signatureBase64 = forge.util.encode64(signatureBytes);

        const response = await fetch('/publicar-encuesta', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: user.email, 
                poll_data_json: pollDataBytes,
                signature_base64: signatureBase64
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Error en el servidor.');
        }

        alert('¡Encuesta creada!');
        closeCreateModal();
        fetchPolls();

    } catch (err) {
        alert("Error al crear encuesta: " + err.message);
    }
}

function handleLogout() {
    privateKey = null;
    user = null;
    polls = [];
    showAuthForm();
}

async function fetchPolls() {
    try {
        const response = await fetch('/get-polls');
        if (!response.ok) throw new Error('No se pudieron cargar las encuestas');
        const pollList = await response.json();
        polls = pollList;
        renderPolls();
    } catch {
        polls = [];
        renderPolls();
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

    polls.forEach(poll => {
        if (!poll.hasVoted) {
            poll.options.forEach((option, index) => {
                const btn = document.querySelector(`[data-poll="${poll.id}"][data-option="${index}"]`);
                if (btn) btn.addEventListener('click', () => handleVote(poll.id, index));
            });
        }

        const resultsBtn = document.getElementById(`results-${poll.id}`);
        if (resultsBtn) resultsBtn.addEventListener('click', () => showResults(poll));
    });
}

function createPollCard(poll) {
    const totalVotes = poll.options.reduce((sum, opt) => sum + opt.votes, 0);

    const optionsHtml = poll.options.map((option, index) => {
        const percentage = totalVotes > 0 ? (option.votes / totalVotes * 100).toFixed(1) : 0;
        const isUserVote = poll.userVote === index;

        if (poll.hasVoted) {
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
    if (!privateKey || !user) {
        alert("Error de sesión.");
        return;
    }

    try {
        const md = forge.md.sha256.create();
        md.update(pollId, 'utf8');
        const signatureBytes = privateKey.sign(md);
        const signatureBase64 = forge.util.encode64(signatureBytes);

        const tokenResponse = await fetch('/solicitar-token-votacion', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_email: user.email,
                poll_id: pollId,
                signature_base64: signatureBase64
            })
        });

        const tokenData = await tokenResponse.json();
        if (!tokenResponse.ok) throw new Error(tokenData.error);
        
        const tokenVotacion = tokenData.token_votacion;

        const poll = polls.find(p => p.id === pollId);
        if (!poll || !poll.clave_publica_pem) {
            throw new Error("Clave pública no encontrada.");
        }

        const publicKey = forge.pki.publicKeyFromPem(poll.clave_publica_pem);

        const votoEnTextoPlano = JSON.stringify({
            vote: optionIndex,
            timestamp: Date.now()
        });

        const votoCifradoBytes = publicKey.encrypt(votoEnTextoPlano, 'RSA-OAEP', {
            md: forge.md.sha256.create()
        });
        const votoCifradoBase64 = forge.util.encode64(votoCifradoBytes);

        const voteResponse = await fetch('/votar', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                poll_id: pollId,
                voto_cifrado: votoCifradoBase64,
                token: tokenVotacion
            })
        });

        if (!voteResponse.ok) {
            const errorData = await voteResponse.json();
            throw new Error(errorData.error);
        }

        alert('¡Tu voto ha sido enviado!');

        const p = polls.find(p => p.id === pollId);
        if (p) {
            p.options[optionIndex].votes++; 
            p.hasVoted = true;
            p.userVote = optionIndex;
            renderPolls();
        }

    } catch (err) {
        alert("Error al emitir el voto: " + err.message);
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

async function showResults(poll) {
    const modal = document.getElementById('results-modal');
    const title = document.getElementById('results-title');
    const content = document.getElementById('results-content');

    title.textContent = poll.title;

    content.innerHTML = '<p>Obteniendo resultados reales del servidor...</p>';
    modal.classList.remove('hidden');

    try {
        const response = await fetch(`/contar-votos/${poll.id}`);
        const data = await response.json();

        if (!response.ok) throw new Error(data.error);

        const serverResults = data.results;
        const totalVotes = data.total_votos;

        content.innerHTML = poll.options.map((option, index) => {
            const votes = serverResults[index] || 0;
            const percentage = totalVotes > 0 ? (votes / totalVotes * 100).toFixed(1) : 0;

            const isUserVote = poll.userVote === index;

            return `
                <div class="result-item">
                    <div class="result-label">
                        <span>${option.text} ${isUserVote ? '✓' : ''}</span>
                        <span>${percentage}%</span>
                    </div>
                    <div class="result-bar-container">
                        <div class="result-bar" style="width: ${percentage}%">
                            ${votes} voto${votes !== 1 ? 's' : ''}
                        </div>
                    </div>
                    <div class="result-votes">${votes} de ${totalVotes} votos</div>
                </div>
            `;
        }).join('');

    } catch (err) {
        content.innerHTML = `<p style="color: red;">Error al cargar resultados: ${err.message}</p>`;
    }
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
    
    const userName = user?.name || user?.email;
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
