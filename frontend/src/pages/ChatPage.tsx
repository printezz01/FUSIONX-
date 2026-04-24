// ═══════════════════════════════════════════════════
// Sentinel AI — Chat Page
// RAG-powered chat about scan findings
// ═══════════════════════════════════════════════════

import { useState, useRef, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { sendChat } from '../api/client';
import type { ChatMessage } from '../types/api';
import { Send, ChevronDown, ChevronRight, Loader } from 'lucide-react';
import toast from 'react-hot-toast';

const SUGGESTED_PROMPTS = [
  'What is the most dangerous issue?',
  'Show the full attack path',
  'What should I fix first?',
  'Any leaked secrets?',
];

export default function ChatPage() {
  const { id } = useParams<{ id: string }>();
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [loading, setLoading] = useState(false);
  const [expandedSources, setExpandedSources] = useState<Set<string>>(new Set());
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSend = async (text?: string) => {
    const question = text || input.trim();
    if (!question || loading || !id) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: question,
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const res = await sendChat(id, question);
      const assistantMsg: ChatMessage = {
        id: `assistant-${Date.now()}`,
        role: 'assistant',
        content: res.answer,
        sources: res.sources || res.context,
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err) {
      toast.error('Failed to get response');
      setInput(question); // Restore text on error
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const toggleSources = (msgId: string) => {
    setExpandedSources((prev) => {
      const next = new Set(prev);
      if (next.has(msgId)) {
        next.delete(msgId);
      } else {
        next.add(msgId);
      }
      return next;
    });
  };

  return (
    <div className="h-full flex flex-col animate-fade-in">
      {/* Header */}
      <div className="mb-4">
        <div className="text-[11px] tracking-[0.2em] uppercase text-[#8a8e7c] font-medium mb-2">
          AI Security Chat
        </div>
        <h1 className="text-2xl font-semibold text-[#2a2e24]">
          Ask anything about your findings.
        </h1>
        <p className="text-[13px] text-[#6b6e60] mt-1">
          Powered by RAG over your scan results. Answers are grounded in actual findings.
        </p>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto min-h-0 space-y-4 pb-4">
        {messages.length === 0 && (
          <div className="flex items-center justify-center h-full">
            <div className="text-center max-w-md">
              <div className="text-6xl mb-4 opacity-20">
                <div className="w-16 h-16 rounded-full bg-sentinel-accent/10 mx-auto flex items-center justify-center">
                  <div className="w-6 h-6 rounded-full bg-sentinel-accent/30" />
                </div>
              </div>
              <p className="text-[#8a8e7c] text-sm">
                Start by asking a question about your scan findings, or try one of the
                suggested prompts below.
              </p>
            </div>
          </div>
        )}

        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
          >
            <div
              className={
                msg.role === 'user'
                  ? 'chat-bubble-user animate-slide-right'
                  : 'chat-bubble-assistant animate-slide-left'
              }
            >
              {/* Render message with basic markdown-like formatting */}
              <div className="text-sm leading-relaxed whitespace-pre-wrap">
                {msg.content.split('\n').map((line, i) => {
                  // Bold text
                  const parts = line.split(/(\*\*.*?\*\*)/g);
                  return (
                    <span key={i}>
                      {parts.map((part, j) => {
                        if (part.startsWith('**') && part.endsWith('**')) {
                          return (
                            <strong key={j} className="font-semibold">
                              {part.slice(2, -2)}
                            </strong>
                          );
                        }
                        return part;
                      })}
                      {i < msg.content.split('\n').length - 1 && <br />}
                    </span>
                  );
                })}
              </div>

              {/* Sources */}
              {msg.role === 'assistant' && msg.sources && msg.sources.length > 0 && (
                <div className="mt-3 pt-3 border-t border-black/5">
                  <button
                    onClick={() => toggleSources(msg.id)}
                    className="text-[11px] text-[#8a8e7c] flex items-center gap-1 hover:text-[#4a4e40] transition-colors"
                  >
                    {expandedSources.has(msg.id) ? (
                      <ChevronDown size={12} />
                    ) : (
                      <ChevronRight size={12} />
                    )}
                    Sources ({msg.sources.length})
                  </button>
                  {expandedSources.has(msg.id) && (
                    <div className="mt-2 space-y-1 animate-fade-in">
                      {msg.sources.map((s) => (
                        <div
                          key={s.id}
                          className="text-[11px] text-[#6b6e60] flex items-center gap-2"
                        >
                          <span className={`status-dot ${s.severity}`} />
                          <span className="font-mono">{s.title}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex justify-start">
            <div className="chat-bubble-assistant animate-slide-left flex items-center gap-2">
              <Loader size={14} className="animate-spin text-sentinel-accent" />
              <span className="text-sm text-[#8a8e7c]">Analyzing findings...</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Suggested prompts (shown when no messages) */}
      {messages.length === 0 && (
        <div className="flex flex-wrap gap-2 mb-3">
          {SUGGESTED_PROMPTS.map((prompt) => (
            <button
              key={prompt}
              onClick={() => handleSend(prompt)}
              className="target-chip text-[12px]"
            >
              {prompt}
            </button>
          ))}
        </div>
      )}

      {/* Input */}
      <div className="glass-panel p-3 flex items-end gap-3">
        <textarea
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Ask about your scan findings..."
          rows={1}
          className="flex-1 bg-transparent border-none outline-none resize-none text-sm text-[#2a2e24] placeholder:text-[#8a8e7c] min-h-[36px] max-h-[120px] py-2 px-3"
          style={{ lineHeight: '1.5' }}
          id="chat-input"
        />
        <button
          onClick={() => handleSend()}
          disabled={!input.trim() || loading}
          className="btn-primary shrink-0"
          id="chat-send-button"
        >
          <Send size={14} />
        </button>
      </div>
    </div>
  );
}
