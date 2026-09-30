// This is the Doubly Linked List implementation used in the Linux kernel.

#ifndef _LIST_H
#define _LIST_H

#include <stddef.h>

struct list_head {
  struct list_head *next, *prev;
};

/**
 * LIST_HEAD_INIT - initialize a &struct list_head's links to point to itself
 * @name: name of the list_head
 */
#define LIST_HEAD_INIT(name) {&(name), &(name)}

/**
 * LIST_HEAD - definition of a &struct list_head with initialization values
 * @name: name of the list_head
 */
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)

#define WRITE_ONCE(x, val)                                                     \
  do {                                                                         \
    *(volatile typeof(x) *)&(x) = (val);                                       \
  } while (0)

/**
 * INIT_LIST_HEAD - Initialize a list_head structure
 * @list: list_head structure to be initialized.
 *
 * Initializes the list_head to point to itself.  If it is a list header,
 * the result is an empty list.
 */
static inline void INIT_LIST_HEAD(struct list_head *list) {
  WRITE_ONCE(list->next, list);
  WRITE_ONCE(list->prev, list);
}

/* Returns the type of a member within a specific struct */
#define typeof_member(T, m) __typeof__(((T *)0)->m)

/* Checks if two expressions have the exact same type */
#define __same_type(a, b)                                                      \
  __builtin_types_compatible_p(__typeof__(a), __typeof__(b))

/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 * WARNING: any const qualifier of @ptr is lost.
 * Do not use container_of() in new code.
 */
#define container_of(ptr, type, member)                                        \
  ({                                                                           \
    static_assert(__same_type(*(ptr), typeof_member(type, member)) ||          \
                      __same_type(*(ptr), void),                               \
                  "pointer type mismatch in container_of()");                  \
    (type *)((void *)(ptr) - offsetof(type, member));                          \
  })

/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 */
#define list_entry(ptr, type, member) container_of(ptr, type, member)

static inline void __list_add(struct list_head *new_node,
                              struct list_head *prev, struct list_head *next) {
  next->prev = new_node;
  new_node->next = next;
  new_node->prev = prev;
  prev->next = new_node;
}

// Adds to the tail (end) of the list
static inline void list_add_tail(struct list_head *new_node,
                                 struct list_head *head) {
  __list_add(new_node, head->prev, head);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __list_del(struct list_head *prev, struct list_head *next) {
  next->prev = prev;
  WRITE_ONCE(prev->next, next);
}

static inline void __list_del_entry(struct list_head *entry) {
  __list_del(entry->prev, entry->next);
}

/*
 * Architectures might want to move the poison pointer offset
 * into some well-recognized area such as 0xdead000000000000,
 * that is also not mappable by user-space exploits:
 */
#ifdef CONFIG_ILLEGAL_POINTER_VALUE
#define POISON_POINTER_DELTA _AC(CONFIG_ILLEGAL_POINTER_VALUE, UL)
#else
#define POISON_POINTER_DELTA 0
#endif

/*
 * These are non-NULL pointers that will result in page faults
 * under normal circumstances, used to verify that nobody uses
 * non-initialized list entries.
 */
#define LIST_POISON1 ((void *)0x100 + POISON_POINTER_DELTA)
#define LIST_POISON2 ((void *)0x122 + POISON_POINTER_DELTA)

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void list_del(struct list_head *entry) {
  __list_del_entry(entry);
  entry->next = LIST_POISON1;
  entry->prev = LIST_POISON2;
}

/**
 * list_is_first -- tests whether @list is the first entry in list @head
 * @list: the entry to test
 * @head: the head of the list
 */
static inline int list_is_first(const struct list_head *list,
                                const struct list_head *head) {
  return list->prev == head;
}

/**
 * list_is_last - tests whether @list is the last entry in list @head
 * @list: the entry to test
 * @head: the head of the list
 */
static inline int list_is_last(const struct list_head *list,
                               const struct list_head *head) {
  return list->next == head;
}

/**
 * list_is_head - tests whether @list is the list @head
 * @list: the entry to test
 * @head: the head of the list
 */
static inline int list_is_head(const struct list_head *list,
                               const struct list_head *head) {
  return list == head;
}

/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 */
#define list_entry(ptr, type, member) container_of(ptr, type, member)

/**
 * list_first_entry - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_first_entry(ptr, type, member)                                    \
  list_entry((ptr)->next, type, member)

/**
 * list_last_entry - get the last element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note, that list is expected to be not empty.
 */
#define list_last_entry(ptr, type, member) list_entry((ptr)->prev, type, member)

/**
 * list_first_entry_or_null - get the first element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note that if the list is empty, it returns NULL.
 */
#define list_first_entry_or_null(ptr, type, member)                            \
  ({                                                                           \
    struct list_head *head__ = (ptr);                                          \
    struct list_head *pos__ = READ_ONCE(head__->next);                         \
    pos__ != head__ ? list_entry(pos__, type, member) : NULL;                  \
  })

/**
 * list_first_entry_or_null_acquire - get the first element from a list with
 * barrier
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note that if the list is empty, it returns NULL.
 */
#define list_first_entry_or_null_acquire(ptr, type, member)                    \
  ({                                                                           \
    struct list_head *head__ = (ptr);                                          \
    struct list_head *pos__ = smp_load_acquire(&head__->next);                 \
    pos__ != head__ ? list_entry(pos__, type, member) : NULL;                  \
  })

/**
 * list_last_entry_or_null - get the last element from a list
 * @ptr:	the list head to take the element from.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 *
 * Note that if the list is empty, it returns NULL.
 */
#define list_last_entry_or_null(ptr, type, member)                             \
  ({                                                                           \
    struct list_head *head__ = (ptr);                                          \
    struct list_head *pos__ = READ_ONCE(head__->prev);                         \
    pos__ != head__ ? list_entry(pos__, type, member) : NULL;                  \
  })

/**
 * list_next_entry - get the next element in list
 * @pos:	the type * to cursor
 * @member:	the name of the list_head within the struct.
 */
#define list_next_entry(pos, member)                                           \
  list_entry((pos)->member.next, typeof(*(pos)), member)

/**
 * list_next_entry_circular - get the next element in list
 * @pos:	the type * to cursor.
 * @head:	the list head to take the element from.
 * @member:	the name of the list_head within the struct.
 *
 * Wraparound if pos is the last element (return the first element).
 * Note, that list is expected to be not empty.
 */
#define list_next_entry_circular(pos, head, member)                            \
  (list_is_last(&(pos)->member, head)                                          \
       ? list_first_entry(head, typeof(*(pos)), member)                        \
       : list_next_entry(pos, member))

/**
 * list_prev_entry - get the prev element in list
 * @pos:	the type * to cursor
 * @member:	the name of the list_head within the struct.
 */
#define list_prev_entry(pos, member)                                           \
  list_entry((pos)->member.prev, typeof(*(pos)), member)

/**
 * list_prev_entry_circular - get the prev element in list
 * @pos:	the type * to cursor.
 * @head:	the list head to take the element from.
 * @member:	the name of the list_head within the struct.
 *
 * Wraparound if pos is the first element (return the last element).
 * Note, that list is expected to be not empty.
 */
#define list_prev_entry_circular(pos, head, member)                            \
  (list_is_first(&(pos)->member, head)                                         \
       ? list_last_entry(head, typeof(*(pos)), member)                         \
       : list_prev_entry(pos, member))

/**
 * list_for_each	-	iterate over a list
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define list_for_each(pos, head)                                               \
  for (pos = (head)->next; !list_is_head(pos, (head)); pos = pos->next)

/**
 * list_for_each_continue - continue iteration over a list
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 *
 * Continue to iterate over a list, continuing after the current position.
 */
#define list_for_each_continue(pos, head)                                      \
  for (pos = pos->next; !list_is_head(pos, (head)); pos = pos->next)

/**
 * list_for_each_prev	-	iterate over a list backwards
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define list_for_each_prev(pos, head)                                          \
  for (pos = (head)->prev; !list_is_head(pos, (head)); pos = pos->prev)

/**
 * list_for_each_safe - iterate over a list safe against removal of list entry
 * @pos:	the &struct list_head to use as a loop cursor.
 * @n:		another &struct list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define list_for_each_safe(pos, n, head)                                       \
  for (pos = (head)->next, n = pos->next; !list_is_head(pos, (head));          \
       pos = n, n = pos->next)

/**
 * list_for_each_prev_safe - iterate over a list backwards safe against removal
 * of list entry
 * @pos:	the &struct list_head to use as a loop cursor.
 * @n:		another &struct list_head to use as temporary storage
 * @head:	the head for your list.
 */
#define list_for_each_prev_safe(pos, n, head)                                  \
  for (pos = (head)->prev, n = pos->prev; !list_is_head(pos, (head));          \
       pos = n, n = pos->prev)

/**
 * list_count_nodes - count nodes in the list
 * @head:	the head for your list.
 */
static inline size_t list_count_nodes(struct list_head *head) {
  struct list_head *pos;
  size_t count = 0;

  list_for_each(pos, head) count++;

  return count;
}

/**
 * list_entry_is_head - test if the entry points to the head of the list
 * @pos:	the type * to cursor
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 */
#define list_entry_is_head(pos, head, member) list_is_head(&pos->member, (head))

/**
 * list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 */
#define list_for_each_entry(pos, head, member)                                 \
  for (pos = list_first_entry(head, typeof(*pos), member);                     \
       !list_entry_is_head(pos, head, member);                                 \
       pos = list_next_entry(pos, member))

/**
 * list_for_each_entry_reverse - iterate backwards over list of given type.
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 */
#define list_for_each_entry_reverse(pos, head, member)                         \
  for (pos = list_last_entry(head, typeof(*pos), member);                      \
       !list_entry_is_head(pos, head, member);                                 \
       pos = list_prev_entry(pos, member))

/**
 * list_prepare_entry - prepare a pos entry for use in
 * list_for_each_entry_continue()
 * @pos:	the type * to use as a start point
 * @head:	the head of the list
 * @member:	the name of the list_head within the struct.
 *
 * Prepares a pos entry for use as a start point in
 * list_for_each_entry_continue().
 */
#define list_prepare_entry(pos, head, member)                                  \
  ((pos) ?: list_entry(head, typeof(*pos), member))

/**
 * list_for_each_entry_continue - continue iteration over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 *
 * Continue to iterate over list of given type, continuing after
 * the current position.
 */
#define list_for_each_entry_continue(pos, head, member)                        \
  for (pos = list_next_entry(pos, member);                                     \
       !list_entry_is_head(pos, head, member);                                 \
       pos = list_next_entry(pos, member))

/**
 * list_for_each_entry_continue_reverse - iterate backwards from the given point
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 *
 * Start to iterate over list of given type backwards, continuing after
 * the current position.
 */
#define list_for_each_entry_continue_reverse(pos, head, member)                \
  for (pos = list_prev_entry(pos, member);                                     \
       !list_entry_is_head(pos, head, member);                                 \
       pos = list_prev_entry(pos, member))

/**
 * list_for_each_entry_from - iterate over list of given type from the current
 * point
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 *
 * Iterate over list of given type, continuing from current position.
 */
#define list_for_each_entry_from(pos, head, member)                            \
  for (; !list_entry_is_head(pos, head, member);                               \
       pos = list_next_entry(pos, member))

/**
 * list_for_each_entry_from_reverse - iterate backwards over list of given type
 *                                    from the current point
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 *
 * Iterate backwards over list of given type, continuing from current position.
 */
#define list_for_each_entry_from_reverse(pos, head, member)                    \
  for (; !list_entry_is_head(pos, head, member);                               \
       pos = list_prev_entry(pos, member))

/**
 * list_for_each_entry_safe - iterate over list of given type safe against
 * removal of list entry
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 */
#define list_for_each_entry_safe(pos, n, head, member)                         \
  for (pos = list_first_entry(head, typeof(*pos), member),                     \
      n = list_next_entry(pos, member);                                        \
       !list_entry_is_head(pos, head, member);                                 \
       pos = n, n = list_next_entry(n, member))

/**
 * list_for_each_entry_safe_continue - continue list iteration safe against
 * removal
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 *
 * Iterate over list of given type, continuing after current point,
 * safe against removal of list entry.
 */
#define list_for_each_entry_safe_continue(pos, n, head, member)                \
  for (pos = list_next_entry(pos, member), n = list_next_entry(pos, member);   \
       !list_entry_is_head(pos, head, member);                                 \
       pos = n, n = list_next_entry(n, member))

/**
 * list_for_each_entry_safe_from - iterate over list from current point safe
 * against removal
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 *
 * Iterate over list of given type from current point, safe against
 * removal of list entry.
 */
#define list_for_each_entry_safe_from(pos, n, head, member)                    \
  for (n = list_next_entry(pos, member);                                       \
       !list_entry_is_head(pos, head, member);                                 \
       pos = n, n = list_next_entry(n, member))

/**
 * list_for_each_entry_safe_reverse - iterate backwards over list safe against
 * removal
 * @pos:	the type * to use as a loop cursor.
 * @n:		another type * to use as temporary storage
 * @head:	the head for your list.
 * @member:	the name of the list_head within the struct.
 *
 * Iterate backwards over list of given type, safe against removal
 * of list entry.
 */
#define list_for_each_entry_safe_reverse(pos, n, head, member)                 \
  for (pos = list_last_entry(head, typeof(*pos), member),                      \
      n = list_prev_entry(pos, member);                                        \
       !list_entry_is_head(pos, head, member);                                 \
       pos = n, n = list_prev_entry(n, member))

#endif
