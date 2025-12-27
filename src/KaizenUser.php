<?php

namespace Kaizen\OAuth;

use Laravel\Socialite\Two\User;

class KaizenUser extends User
{
    /**
     * Get the Minecraft UUID.
     */
    public function getMinecraftUuid(): ?string
    {
        return $this->attributes['minecraft_uuid'] ?? null;
    }

    /**
     * Get the Minecraft username.
     */
    public function getMinecraftUsername(): ?string
    {
        return $this->attributes['minecraft_username'] ?? null;
    }

    /**
     * Check if the user has a linked Minecraft account.
     */
    public function hasMinecraftAccount(): bool
    {
        return ! empty($this->getMinecraftUuid());
    }

    /**
     * Get a specific attribute from the raw user data.
     */
    public function getAttribute(string $key, mixed $default = null): mixed
    {
        return $this->user[$key] ?? $default;
    }

    /**
     * Get all raw attributes.
     */
    public function getAttributes(): array
    {
        return $this->user;
    }

    /**
     * Check if the user has a specific role.
     */
    public function hasRole(string $role): bool
    {
        $roles = $this->getAttribute('roles', []);

        return in_array($role, $roles);
    }

    /**
     * Check if the user is an admin.
     */
    public function isAdmin(): bool
    {
        return $this->hasRole('admin');
    }

    /**
     * Get the user's locale preference.
     */
    public function getLocale(): string
    {
        return $this->getAttribute('locale', 'en');
    }
}
