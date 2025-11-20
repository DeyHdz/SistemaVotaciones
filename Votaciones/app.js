let user = null;
let privateKey = null;
let polls = [];
let currentChart = null; // Para almacenar la instancia del gráfico

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
    document.getElementById('upload-key-btn').addEventListener('click', () => {
        document.getElementById('private-key-file').click();
    });
    document.getElementById('private-key-file').addEventListener('change', handleKeyFileUpload);

    const createBtn = document.getElementById('create-poll-btn');
    if (createBtn) {
        createBtn.addEventListener('click', openCreateModal);
    }
    
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
        const privateKeyPem = forge.pki.privateKeyToPem(keyPair.privateKey);

        const response = await fetch('/registrar', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: name,
                email: email,
                password: password,
                public_key_pem: publicKeyPem
            })
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || 'Error al registrar en el servidor.');
        }

        const result = await response.json();

        downloadPrivateKey(privateKeyPem, email);
        
        document.getElementById('signup-form').reset();
        
        alert(`¡Registro exitoso como ${result.rol}! Tu clave privada se ha descargado. GUÁRDALA EN UN LUGAR SEGURO, la necesitarás para iniciar sesión.`);
        
        const authCards = document.querySelectorAll('.auth-card');
        authCards[1].classList.add('hidden');
        authCards[0].classList.remove('hidden');

    } catch (err) {
        alert("Error al registrar: " + err.message);
    }
}

function downloadPrivateKey(privateKeyPem, email) {
    const blob = new Blob([privateKeyPem], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${email.replace('@', '_')}_private_key.pem`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function handleKeyFileUpload(e) {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
        const privateKeyPem = event.target.result;
        document.getElementById('login-key-display').textContent = 'Clave cargada: ' + file.name;
        document.getElementById('login-key-display').dataset.key = privateKeyPem;
    };
    reader.readAsText(file);
}

async function handleLogin(e) {
    e.preventDefault();

    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    const privateKeyPem = document.getElementById('login-key-display').dataset.key;

    if (!privateKeyPem) {
        alert("Por favor, carga tu clave privada (.pem)");
        return;
    }

    if (!password) {
        alert("Por favor, ingresa tu contraseña");
        return;
    }

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: email,
                password: password,
                private_key_pem: privateKeyPem
            })
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.error || 'Error al iniciar sesión');
        }

        const result = await response.json();
        
        privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
        user = result.user;

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

    if (user.rol !== 'admin') {
        alert("Solo los administradores pueden crear encuestas");
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
    document.getElementById('login-email').value = '';
    document.getElementById('login-password').value = '';
    document.getElementById('login-key-display').textContent = '';
    document.getElementById('login-key-display').dataset.key = '';
    document.getElementById('private-key-file').value = '';
    showAuthForm();
}

async function fetchPolls() {
    try {
        const url = user ? `/get-polls?user_email=${encodeURIComponent(user.email)}` : '/get-polls';
        const response = await fetch(url);
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

    const createBtn = document.getElementById('create-poll-btn');
    if (user && user.rol === 'admin') {
        createBtn.style.display = 'flex';
    } else {
        createBtn.style.display = 'none';
    }

    if (polls.length === 0) {
        container.innerHTML = '';
        emptyState.classList.remove('hidden');
        return;
    }

    emptyState.classList.add('hidden');
    container.innerHTML = polls.map(poll => createPollCard(poll)).join('');

    polls.forEach(poll => {
        if (!poll.hasVoted && user.rol === 'voter') {
            poll.options.forEach((option, index) => {
                const btn = document.querySelector(`[data-poll="${poll.id}"][data-option="${index}"]`);
                if (btn) btn.addEventListener('click', () => handleVote(poll.id, index));
            });
        }

        const resultsBtn = document.getElementById(`results-${poll.id}`);
        if (resultsBtn) resultsBtn.addEventListener('click', () => showResults(poll));
        
        const deleteBtn = document.getElementById(`delete-${poll.id}`);
        if (deleteBtn) {
            deleteBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                handleDeletePoll(poll.id);
            });
        }
    });
}

function createPollCard(poll) {
    const totalVotes = poll.totalVotes || 0;

    const optionsHtml = poll.options.map((option, index) => {
        const percentage = totalVotes > 0 ? ((option.votes || 0) / totalVotes * 100).toFixed(1) : 0;
        const isUserVote = poll.userVote === index;

        if (poll.hasVoted || user.rol === 'admin') {
            return `
                <div class="poll-option voted" style="--percentage: ${percentage}%">
                    <button data-percentage="${percentage}%" disabled style="background: linear-gradient(90deg, ${isUserVote ? '#3b82f6' : '#e5e7eb'} ${percentage}%, #f9fafb ${percentage}%);">
                        ${option.text} ${isUserVote ? '✓' : ''}
                    </button>
                </div>
            `;
        } else if (user.rol === 'voter') {
            return `
                <div class="poll-option">
                    <button data-poll="${poll.id}" data-option="${index}">
                        ${option.text}
                    </button>
                </div>
            `;
        } else {
            return '';
        }
    }).join('');

    const footerHtml = user.rol === 'admin' 
        ? `<div class="poll-footer">
                <span class="vote-count">${totalVotes} voto${totalVotes !== 1 ? 's' : ''}</span>
                <div class="poll-actions">
                    <button class="btn-results" id="results-${poll.id}">Resultados</button>
                    <button class="btn-delete" id="delete-${poll.id}">Borrar</button>
                </div>
           </div>`
        : `<div class="poll-footer">
                <span class="vote-count">${totalVotes} voto${totalVotes !== 1 ? 's' : ''}</span>
           </div>`;

    return `
        <div class="poll-card">
            <h3>${poll.title}</h3>
            ${optionsHtml}
            ${footerHtml}
        </div>
    `;
}

async function handleVote(pollId, optionIndex) {
    if (!privateKey || !user) {
        alert("Error de sesión.");
        return;
    }

    if (user.rol !== 'voter') {
        alert("Solo los votantes pueden votar en encuestas");
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
        fetchPolls();

    } catch (err) {
        alert("Error al emitir el voto: " + err.message);
    }
}

async function handleDeletePoll(pollId) {
    if (!user || user.rol !== 'admin') {
        alert("Acción no permitida.");
        return;
    }

    if (!confirm('¿Estás seguro de que quieres borrar esta encuesta? Esta acción es irreversible y borrará todos sus votos.')) {
        return;
    }

    try {
        const response = await fetch(`/borrar-encuesta/${pollId}?user_email=${encodeURIComponent(user.email)}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Error del servidor');
        }

        alert('Encuesta borrada exitosamente.');
        fetchPolls();

    } catch (err) {
        alert('Error al borrar la encuesta: ' + err.message);
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
    if (user.rol !== 'admin') {
        alert("Solo los administradores pueden crear encuestas");
        return;
    }
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
    if (user.rol !== 'admin') {
        alert("Solo los administradores pueden ver los resultados detallados");
        return;
    }

    const modal = document.getElementById('results-modal');
    const title = document.getElementById('results-title');
    const content = document.getElementById('results-content');

    title.textContent = poll.title;

    content.innerHTML = `
        <div class="results-loading">
            <div class="loader-small"></div>
            <p>Obteniendo resultados reales del servidor...</p>
        </div>
    `;
    modal.classList.remove('hidden');

    try {
        const response = await fetch(`/contar-votos/${poll.id}?user_email=${encodeURIComponent(user.email)}`);
        const data = await response.json();

        if (!response.ok) throw new Error(data.error);

        const serverResults = data.results;
        const totalVotes = data.total_votos;

        // Preparar datos para la gráfica
        const labels = poll.options.map(opt => opt.text);
        const votes = poll.options.map((opt, idx) => serverResults[idx] || 0);
        const colors = generateColors(poll.options.length);

        // Destruir gráfica anterior si existe
        if (currentChart) {
            currentChart.destroy();
            currentChart = null;
        }

        content.innerHTML = `
            <div class="chart-type-selector">
                <button class="chart-type-btn active" data-type="bar">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <line x1="12" y1="20" x2="12" y2="10"></line>
                        <line x1="18" y1="20" x2="18" y2="4"></line>
                        <line x1="6" y1="20" x2="6" y2="16"></line>
                    </svg>
                    Barras
                </button>
                <button class="chart-type-btn" data-type="pie">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21.21 15.89A10 10 0 1 1 8 2.83"></path>
                        <path d="M22 12A10 10 0 0 0 12 2v10z"></path>
                    </svg>
                    Pastel
                </button>
                <button class="chart-type-btn" data-type="doughnut">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="10"></circle>
                        <circle cx="12" cy="12" r="6"></circle>
                    </svg>
                    Dona
                </button>
                <button class="chart-type-btn" data-type="line">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
                    </svg>
                    Línea
                </button>
            </div>
            <div class="chart-container">
                <canvas id="results-chart"></canvas>
            </div>
            <div class="results-details">
                <h3>Detalles de votación</h3>
                <div class="results-summary">
                    <div class="summary-item">
                        <span class="summary-label">Total de votos:</span>
                        <span class="summary-value">${totalVotes}</span>
                    </div>
                </div>
                ${poll.options.map((option, index) => {
                    const optVotes = serverResults[index] || 0;
                    const percentage = totalVotes > 0 ? (optVotes / totalVotes * 100).toFixed(1) : 0;
                    return `
                        <div class="result-item">
                            <div class="result-label">
                                <span class="option-name">
                                    <span class="color-indicator" style="background-color: ${colors[index]}"></span>
                                    ${option.text}
                                </span>
                                <span class="option-percentage">${percentage}%</span>
                            </div>
                            <div class="result-bar-container">
                                <div class="result-bar" style="width: ${percentage}%; background-color: ${colors[index]}">
                                    ${optVotes} voto${optVotes !== 1 ? 's' : ''}
                                </div>
                            </div>
                        </div>
                    `;
                }).join('')}
            </div>
        `;

        // Crear gráfica inicial (barras)
        createChart('bar', labels, votes, colors, totalVotes);

        // Agregar event listeners para cambiar tipo de gráfica
        document.querySelectorAll('.chart-type-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                document.querySelectorAll('.chart-type-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                const type = btn.dataset.type;
                createChart(type, labels, votes, colors, totalVotes);
            });
        });

    } catch (err) {
        content.innerHTML = `
            <div class="error-message">
                <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="12" y1="8" x2="12" y2="12"></line>
                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                </svg>
                <p>Error al cargar resultados: ${err.message}</p>
            </div>
        `;
    }
}

function createChart(type, labels, votes, colors, totalVotes) {
    // Destruir gráfica anterior
    if (currentChart) {
        currentChart.destroy();
    }

    const ctx = document.getElementById('results-chart');
    if (!ctx) return;

    const config = {
        type: type,
        data: {
            labels: labels,
            datasets: [{
                label: 'Votos',
                data: votes,
                backgroundColor: colors,
                borderColor: colors.map(c => c.replace('0.8', '1')),
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            aspectRatio: type === 'bar' || type === 'line' ? 2 : 1.5,
            plugins: {
                legend: {
                    display: type === 'pie' || type === 'doughnut',
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        font: {
                            size: 12
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const value = context.parsed.y || context.parsed;
                            const percentage = totalVotes > 0 ? ((value / totalVotes) * 100).toFixed(1) : 0;
                            return `${context.label}: ${value} votos (${percentage}%)`;
                        }
                    }
                }
            },
            scales: type === 'bar' || type === 'line' ? {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            } : {}
        }
    };

    currentChart = new Chart(ctx, config);
}

function generateColors(count) {
    const baseColors = [
        'rgba(59, 130, 246, 0.8)',   // Blue
        'rgba(16, 185, 129, 0.8)',   // Green
        'rgba(239, 68, 68, 0.8)',    // Red
        'rgba(245, 158, 11, 0.8)',   // Orange
        'rgba(139, 92, 246, 0.8)',   // Purple
        'rgba(236, 72, 153, 0.8)',   // Pink
        'rgba(20, 184, 166, 0.8)',   // Teal
        'rgba(251, 191, 36, 0.8)',   // Amber
        'rgba(99, 102, 241, 0.8)',   // Indigo
        'rgba(34, 197, 94, 0.8)',    // Emerald
    ];

    if (count <= baseColors.length) {
        return baseColors.slice(0, count);
    }

    // Si necesitamos más colores, generamos aleatorios
    const colors = [...baseColors];
    for (let i = baseColors.length; i < count; i++) {
        const hue = (i * 137.508) % 360; // Golden angle
        colors.push(`hsla(${hue}, 70%, 60%, 0.8)`);
    }
    return colors;
}

function closeResultsModal() {
    document.getElementById('results-modal').classList.add('hidden');
    // Destruir gráfica al cerrar
    if (currentChart) {
        currentChart.destroy();
        currentChart = null;
    }
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
    const userRole = user?.rol === 'admin' ? 'Administrador' : 'Votante';
    document.getElementById('user-welcome').textContent = `Bienvenido, ${userName} (${userRole})`;
}

function showSignupForm(e) {
    e.preventDefault();
    const authCards = document.querySelectorAll('.auth-card');
    authCards[0].classList.add('hidden');
    authCards[1].classList.remove('hidden');
}

function showLoginForm(e) {
    e.preventDefault();
    const authCards = document.querySelectorAll('.auth-card');
    authCards[0].classList.remove('hidden');
    authCards[1].classList.add('hidden');
}