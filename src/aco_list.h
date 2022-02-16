#ifndef ACO_LIST_H
#define ACO_LIST_H

template <typename Element>
struct List {
  public:
    Element data;
    List *prev, *next;

  public:
    inline void add(List *_new)
    {
        List::__add(_new, this, this->next);
    }

    inline void add_tail(List *_new)
    {
        List::__add(_new, this->prev, this);
    }

    inline void del(List *entry)
    {
        List::__del(entry->prev, entry->next);
        List::__clr(entry);
    }

    inline bool empty() const
    {
#ifndef LIST_CAREFUL
        return this->next == this;
#else
        const List *nxt = this->next;
        return (nxt == this) && (nxt == this->prev);
#endif
    }

    inline bool is_last_of(const List *lst)
    {
        return this->next == lst;
    }

  protected:
    static inline void __clr(List *lst)
    {
        lst->next = lst->prev = lst;
    }

    static inline void __add(List *_new, List *prev, List *next)
    {
        next->prev = _new;
        _new->next = next;
        _new->prev = prev;
        prev->next = _new;
    }

    static inline void __del(List *prev, List *next)
    {
        next->prev = prev;
        prev->next = next;
    }

    static inline void __replace(List *_old, List *_new)
    {
        _new->next = _old->next;
        _new->next->prev = _new;
        _new->prev = _old->prev;
        _new->prev->next = _new;
    }
};

#endif
