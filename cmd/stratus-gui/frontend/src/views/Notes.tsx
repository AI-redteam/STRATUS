import React, { useState, useEffect } from 'react';
import type { NoteInfo } from '../types/api';
import * as api from '../hooks/useWails';
import { DataTable, Column } from '../components/shared/DataTable';
import { DetailPanel, DetailRow } from '../components/shared/DetailPanel';
import { Badge } from '../components/shared/Badge';
import { LoadingState, ErrorBanner, Spinner } from '../components/shared/Spinner';
import { formatDate, shortUUID } from '../lib/format';

export function Notes() {
  const [notes, setNotes] = useState<NoteInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<NoteInfo | null>(null);

  // Filters
  const [sessionFilter, setSessionFilter] = useState('');
  const [runFilter, setRunFilter] = useState('');
  const [nodeFilter, setNodeFilter] = useState('');

  // Add note state
  const [showAdd, setShowAdd] = useState(false);
  const [newContent, setNewContent] = useState('');
  const [newSession, setNewSession] = useState('');
  const [newRun, setNewRun] = useState('');
  const [newNode, setNewNode] = useState('');
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState('');

  // Edit state
  const [editing, setEditing] = useState(false);
  const [editContent, setEditContent] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => { loadData(); }, [sessionFilter, runFilter, nodeFilter]);

  const loadData = async () => {
    setLoading(true);
    setError('');
    try {
      const result = await api.listNotes(sessionFilter, runFilter, nodeFilter);
      setNotes(result || []);
    } catch (e: any) {
      setError(typeof e === 'string' ? e : (e?.message || 'Failed to load notes'));
    }
    setLoading(false);
  };

  const handleAdd = async () => {
    if (!newContent.trim()) return;
    setAddError('');
    setAdding(true);
    try {
      await api.addNote({
        content: newContent,
        session_uuid: newSession || undefined,
        run_uuid: newRun || undefined,
        node_id: newNode || undefined,
      });
      setShowAdd(false);
      setNewContent('');
      setNewSession('');
      setNewRun('');
      setNewNode('');
      await loadData();
    } catch (e: any) {
      setAddError(typeof e === 'string' ? e : (e?.message || 'Failed to add note'));
    }
    setAdding(false);
  };

  const handleEdit = (note: NoteInfo) => {
    setEditing(true);
    setEditContent(note.content);
  };

  const handleSaveEdit = async () => {
    if (!selected || !editContent.trim()) return;
    setSaving(true);
    try {
      await api.updateNote(selected.uuid, editContent);
      setEditing(false);
      setSelected({ ...selected, content: editContent, updated_at: new Date().toISOString() });
      await loadData();
    } catch (e: any) {
      alert(typeof e === 'string' ? e : (e?.message || 'Failed to update note'));
    }
    setSaving(false);
  };

  const handleDelete = async (note: NoteInfo) => {
    if (!confirm('Delete this note? This cannot be undone.')) return;
    try {
      await api.deleteNote(note.uuid);
      setSelected(null);
      await loadData();
    } catch (e: any) {
      alert(typeof e === 'string' ? e : (e?.message || 'Failed to delete note'));
    }
  };

  const firstLine = (content: string) => {
    const line = content.split('\n')[0];
    return line.length > 80 ? line.slice(0, 77) + '...' : line;
  };

  const columns: Column<NoteInfo>[] = [
    { key: 'uuid', header: 'UUID', render: n => <span className="font-mono text-xs">{shortUUID(n.uuid)}</span> },
    { key: 'content', header: 'Content', render: n => <span className="text-sm">{firstLine(n.content)}</span> },
    { key: 'session_uuid', header: 'Session', render: n => n.session_uuid ? <span className="font-mono text-xs text-stratus-muted">{shortUUID(n.session_uuid)}</span> : <span className="text-xs text-stratus-muted">{'\u2014'}</span> },
    { key: 'run_uuid', header: 'Run', render: n => n.run_uuid ? <span className="font-mono text-xs text-stratus-muted">{shortUUID(n.run_uuid)}</span> : <span className="text-xs text-stratus-muted">{'\u2014'}</span> },
    { key: 'created_at', header: 'Created', render: n => <span className="text-xs text-stratus-muted">{formatDate(n.created_at)}</span> },
  ];

  if (loading) return <LoadingState message="Loading notes..." />;
  if (error) return <ErrorBanner message={error} onRetry={loadData} />;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold">Notes</h1>
          <Badge label={`${notes.length} total`} variant="purple" />
        </div>
        <div className="flex items-center gap-2">
          <input
            type="text"
            className="input-field text-xs w-28 font-mono"
            placeholder="Session UUID"
            value={sessionFilter}
            onChange={e => setSessionFilter(e.target.value)}
          />
          <input
            type="text"
            className="input-field text-xs w-28 font-mono"
            placeholder="Run UUID"
            value={runFilter}
            onChange={e => setRunFilter(e.target.value)}
          />
          <input
            type="text"
            className="input-field text-xs w-28 font-mono"
            placeholder="Node ID"
            value={nodeFilter}
            onChange={e => setNodeFilter(e.target.value)}
          />
          <button onClick={() => setShowAdd(true)} className="btn-primary text-sm">
            + Add Note
          </button>
        </div>
      </div>

      <div className="card">
        <DataTable
          columns={columns}
          data={notes}
          onRowClick={setSelected}
          emptyMessage="No notes yet. Add a note to record observations."
        />
      </div>

      {/* Note detail panel */}
      <DetailPanel
        open={!!selected && !showAdd}
        onClose={() => { setSelected(null); setEditing(false); }}
        title="Note Detail"
      >
        {selected && (
          <>
            <DetailRow label="UUID" value={selected.uuid} mono />
            {selected.session_uuid && <DetailRow label="Session" value={selected.session_uuid} mono />}
            {selected.run_uuid && <DetailRow label="Run" value={selected.run_uuid} mono />}
            {selected.node_id && <DetailRow label="Node" value={selected.node_id} mono />}
            <DetailRow label="Created" value={formatDate(selected.created_at)} />
            <DetailRow label="Updated" value={formatDate(selected.updated_at)} />
            <DetailRow label="Author" value={selected.created_by} />

            <div className="mt-4 pt-4 border-t border-stratus-border">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-xs text-stratus-muted uppercase">Content</h4>
                {!editing && (
                  <button onClick={() => handleEdit(selected)} className="btn-ghost text-xs">Edit</button>
                )}
              </div>
              {editing ? (
                <div className="space-y-2">
                  <textarea
                    className="input-field font-mono text-xs h-48 resize-y w-full"
                    value={editContent}
                    onChange={e => setEditContent(e.target.value)}
                  />
                  <div className="flex gap-2">
                    <button
                      onClick={handleSaveEdit}
                      disabled={saving}
                      className="btn-primary text-xs flex items-center gap-1"
                    >
                      {saving && <Spinner size="sm" />}
                      Save
                    </button>
                    <button onClick={() => setEditing(false)} className="btn-ghost text-xs">Cancel</button>
                  </div>
                </div>
              ) : (
                <pre className="bg-stratus-bg rounded p-3 text-xs font-mono overflow-auto max-h-64 whitespace-pre-wrap break-words">
                  {selected.content}
                </pre>
              )}
            </div>

            <div className="mt-4 pt-4 border-t border-stratus-border">
              <button onClick={() => handleDelete(selected)} className="btn-danger text-xs">
                Delete Note
              </button>
            </div>
          </>
        )}
      </DetailPanel>

      {/* Add note panel */}
      <DetailPanel
        open={showAdd}
        onClose={() => { setShowAdd(false); setAddError(''); }}
        title="Add Note"
      >
        <div className="space-y-4">
          <div>
            <label className="block text-xs text-stratus-muted uppercase mb-1">
              Content <span className="text-red-400">*</span>
            </label>
            <textarea
              className="input-field font-mono text-xs h-48 resize-y w-full"
              placeholder="Write your note here..."
              value={newContent}
              onChange={e => setNewContent(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs text-stratus-muted uppercase mb-1">Session UUID (optional)</label>
            <input
              type="text"
              className="input-field font-mono text-xs"
              placeholder="Link to a session..."
              value={newSession}
              onChange={e => setNewSession(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs text-stratus-muted uppercase mb-1">Run UUID (optional)</label>
            <input
              type="text"
              className="input-field font-mono text-xs"
              placeholder="Link to a module run..."
              value={newRun}
              onChange={e => setNewRun(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs text-stratus-muted uppercase mb-1">Node ID (optional)</label>
            <input
              type="text"
              className="input-field font-mono text-xs"
              placeholder="Link to a graph node..."
              value={newNode}
              onChange={e => setNewNode(e.target.value)}
            />
          </div>

          {addError && <ErrorBanner message={addError} />}

          <button
            onClick={handleAdd}
            disabled={adding || !newContent.trim()}
            className="btn-primary w-full flex items-center justify-center gap-2"
          >
            {adding && <Spinner size="sm" />}
            {adding ? 'Adding...' : 'Add Note'}
          </button>
        </div>
      </DetailPanel>
    </div>
  );
}
