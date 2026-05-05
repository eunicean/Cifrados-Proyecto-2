import { useMemo, useState } from 'react'
import './Chats.css'

const demoGroups = [
  {
    id: 'grp-finanzas',
    name: 'Finanzas',
    description: 'Equipo de revisión interna',
    members: ['Ana', 'Carlos', 'María', 'Luis'],
    lastMessage: 'Revisemos el documento antes de enviarlo.',
    unread: 3,
  },
  {
    id: 'grp-proyecto',
    name: 'Proyecto Cifrados',
    description: 'Mensajería segura grupal',
    members: ['Gabriel', 'Sofía', 'Diego'],
    lastMessage: 'Ya quedó listo el módulo de cifrado híbrido.',
    unread: 1,
  },
  {
    id: 'grp-general',
    name: 'General',
    description: 'Canal principal del equipo',
    members: ['Equipo completo'],
    lastMessage: 'Recordatorio: hacer pruebas antes del commit.',
    unread: 0,
  },
]

const demoMessages = {
  'grp-finanzas': [
    {
      id: 'msg-1',
      sender: 'Ana',
      content: 'Hola equipo, ya subí el documento para revisión.',
      time: '09:20',
      own: false,
    },
    {
      id: 'msg-2',
      sender: 'Tú',
      content: 'Perfecto, lo reviso y les aviso si encuentro algo.',
      time: '09:24',
      own: true,
    },
    {
      id: 'msg-3',
      sender: 'Carlos',
      content: 'También validaré que los archivos estén completos.',
      time: '09:27',
      own: false,
    },
  ],
  'grp-proyecto': [
    {
      id: 'msg-4',
      sender: 'Sofía',
      content: 'Ya está lista la parte del cifrado híbrido para integrar.',
      time: '10:10',
      own: false,
    },
    {
      id: 'msg-5',
      sender: 'Tú',
      content: 'Genial, yo estoy armando la pantalla de chats.',
      time: '10:14',
      own: true,
    },
    {
      id: 'msg-6',
      sender: 'Diego',
      content: 'Después conectamos el envío real con el endpoint de mensajes.',
      time: '10:18',
      own: false,
    },
  ],
  'grp-general': [
    {
      id: 'msg-7',
      sender: 'Sistema',
      content: 'Bienvenido al canal general de Blu.',
      time: '08:00',
      own: false,
    },
  ],
}

function Chats() {
  const [groups, setGroups] = useState(demoGroups)
  const [selectedGroupId, setSelectedGroupId] = useState(demoGroups[0].id)
  const [messagesByGroup, setMessagesByGroup] = useState(demoMessages)
  const [messageText, setMessageText] = useState('')
  const [searchTerm, setSearchTerm] = useState('')

  const selectedGroup = useMemo(() => {
    return groups.find((group) => group.id === selectedGroupId)
  }, [groups, selectedGroupId])

  const currentMessages = messagesByGroup[selectedGroupId] || []

  const filteredGroups = groups.filter((group) =>
    group.name.toLowerCase().includes(searchTerm.toLowerCase()),
  )

  function handleSelectGroup(groupId) {
    setSelectedGroupId(groupId)

    setGroups((currentGroups) =>
      currentGroups.map((group) =>
        group.id === groupId ? { ...group, unread: 0 } : group,
      ),
    )
  }

  function handleSendMessage(event) {
    event.preventDefault()

    const cleanMessage = messageText.trim()

    if (!cleanMessage) return

    const newMessage = {
      id: crypto.randomUUID(),
      sender: 'Tú',
      content: cleanMessage,
      time: new Date().toLocaleTimeString('es-GT', {
        hour: '2-digit',
        minute: '2-digit',
      }),
      own: true,
    }

    setMessagesByGroup((currentMessagesByGroup) => ({
      ...currentMessagesByGroup,
      [selectedGroupId]: [
        ...(currentMessagesByGroup[selectedGroupId] || []),
        newMessage,
      ],
    }))

    setGroups((currentGroups) =>
      currentGroups.map((group) =>
        group.id === selectedGroupId
          ? { ...group, lastMessage: cleanMessage }
          : group,
      ),
    )

    setMessageText('')
  }

  return (
    <main className="chats-page">
      <aside className="chats-sidebar">
        <div className="chats-brand">
          <div className="chats-logo">B</div>

          <div>
            <strong>Blu</strong>
            <span>Chats grupales</span>
          </div>
        </div>

        <div className="chats-search">
          <input
            type="text"
            placeholder="Buscar grupo..."
            value={searchTerm}
            onChange={(event) => setSearchTerm(event.target.value)}
          />
        </div>

        <section className="groups-list">
          {filteredGroups.length === 0 ? (
            <p className="empty-text">No se encontraron grupos.</p>
          ) : (
            filteredGroups.map((group) => (
              <button
                key={group.id}
                className={`group-chat-card ${
                  selectedGroupId === group.id ? 'active' : ''
                }`}
                onClick={() => handleSelectGroup(group.id)}
              >
                <div className="group-icon">
                  {group.name.charAt(0).toUpperCase()}
                </div>

                <div className="group-info">
                  <div className="group-title-row">
                    <strong>{group.name}</strong>

                    {group.unread > 0 && (
                      <span className="unread-badge">{group.unread}</span>
                    )}
                  </div>

                  <span>{group.lastMessage}</span>
                </div>
              </button>
            ))
          )}
        </section>

        <button className="new-group-button">
          + Nuevo grupo
        </button>
      </aside>

      <section className="chat-main">
        <header className="chat-header">
          <div>
            <p className="section-label">Chat activo</p>
            <h1>{selectedGroup?.name || 'Grupo'}</h1>
            <span>{selectedGroup?.description}</span>
          </div>

          <div className="chat-status">
            <span className="status-dot"></span>
            Grupo privado
          </div>
        </header>

        <section className="messages-area">
          {currentMessages.map((message) => (
            <article
              key={message.id}
              className={`message-bubble ${message.own ? 'own' : ''}`}
            >
              <div className="message-meta">
                <strong>{message.sender}</strong>
                <span>{message.time}</span>
              </div>

              <p>{message.content}</p>
            </article>
          ))}
        </section>

        <form className="message-composer" onSubmit={handleSendMessage}>
          <input
            type="text"
            placeholder="Escribe un mensaje para el grupo..."
            value={messageText}
            onChange={(event) => setMessageText(event.target.value)}
          />

          <button type="submit">
            Enviar
          </button>
        </form>
      </section>

      <aside className="chat-details">
        <div className="details-card">
          <div className="details-avatar">
            {selectedGroup?.name?.charAt(0).toUpperCase() || 'G'}
          </div>

          <h2>{selectedGroup?.name}</h2>
          <p>{selectedGroup?.description}</p>
        </div>

        <div className="details-card">
          <p className="section-label">Miembros</p>

          <div className="members-list">
            {selectedGroup?.members.map((member) => (
              <div className="member-item" key={member}>
                <span>{member.charAt(0).toUpperCase()}</span>
                <strong>{member}</strong>
              </div>
            ))}
          </div>
        </div>

        <div className="details-card">
          <p className="section-label">Seguridad</p>

          <div className="security-list">
            <span>Grupo privado</span>
            <span>Mensajes preparados para cifrado</span>
            <span>Integración futura con API REST</span>
          </div>
        </div>
      </aside>
    </main>
  )
}

export default Chats