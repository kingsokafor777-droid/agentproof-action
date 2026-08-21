'use strict';

/** @param {string} token */
function createGitHubClient(token) {
  if (!token) throw new Error('github-token is required when comment-pr is true.');
  /** @param {string} method @param {string} endpoint @param {object} [body] */
  async function request(method, endpoint, body = undefined) {
    const response = await fetch(`https://api.github.com${endpoint}`, {
      method,
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'content-type': 'application/json',
        'x-github-api-version': '2022-11-28'
      },
      body: body ? JSON.stringify(body) : undefined
    });
    if (!response.ok)
      throw new Error(`GitHub PR evidence request failed with HTTP ${response.status}.`);
    return response.status === 204 ? null : response.json();
  }
  return {
    /** @param {string} owner @param {string} repo @param {number} issueNumber */
    listComments(owner, repo, issueNumber) {
      return request(
        'GET',
        `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/${issueNumber}/comments?per_page=100`
      );
    },
    /** @param {string} owner @param {string} repo @param {number} commentId @param {string} body */
    updateComment(owner, repo, commentId, body) {
      return request(
        'PATCH',
        `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/comments/${commentId}`,
        { body }
      );
    },
    /** @param {string} owner @param {string} repo @param {number} issueNumber @param {string} body */
    createComment(owner, repo, issueNumber, body) {
      return request(
        'POST',
        `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/${issueNumber}/comments`,
        { body }
      );
    }
  };
}

module.exports = { createGitHubClient };
